# AFLNet 变异策略

**本文档默认 `state_aware_mode = 1`**

AFLNet 经过前期处理后，进入一个死循环。首先通过 `choose_target_state` 选择目标状态 `target_state_id`。

状态选择策略类型(通过 -q 参数进行选择）：

- RANDOM_SELECTION: 随机选择
- ROUND_ROBIN: 轮转
- FAVOR: 偏好

#### `struct queue_entry`

```c
struct queue_entry {
  u8* fname;
  u32 len;
  u8 cal_failed,
  trim_done,
  was_fuzzed,
	passed_det,
  var_behavior,
  favored,
  fs_redundant;
  u32 bitmap_size,
  exec_cksum;
  u64 exec_us,
  handicap,
  depth;
  u8* trace_mini; // trace_bits 的压缩版本，将字节压缩为比特
  u32 tc_ref;
}
```



#### `calibrate_case`

作用：对种子文件进行校验和评分。

过程：

1. 如果 `q->exec_cksum` 不为0，需要将 `trace_bits` 保存到 `first_trace`.
2. 进行多次测试
3. 在每次测试中，并不会修改测试数据，然后比较哈希值两次间的运行路径是否有不同；

#### `common_fuzz_stuff`

阶段：

1. 调用 `extract_requests` 将 `out_buf` 进行分割
2. 对于每个 region，创建一个新的message，添加到 `kl_messages` 队尾。
3. 在构造完成后，将变异后的 M2 部分在原本的 messages 中替换掉原来的 M2 部分。

#### `update_fuzzes`

作用：解析 response buffer 中的内容，获取状态码序列并进行遍历。对于某个唯一的状态码，从 `khms_states` 获取对应的状态，如果存在，则将对应的 `fuzzs++`。

`khms_states` 中的状态是在 `update_state_aware_variables` 中添加的。 

#### `fuzz_one`

###### 关键变量

- `pending_favored`
- `queued_paths`: 队列中的测试用例数

###### 关键参数（跳出当前测试用例的概率参数）

- `SKIP_TO_NEW_PROB`: 当队列中存在新的 favored 的测试用例
- `SKIP_NFAV_NEW_PROB`：当队列中不存在新的 favored，且当前用例没有进行fuzz
- `SKIP_NFAV_OLD_PROB`: 当队列中不存在新的 favored，当前用例已经进行fuzz

阶段：

1. 根据 AFLNet 论文，每份用例被分成三个阶段：

   - M1: 到达指定状态 $s$ 所需的部分；
   - M2: 包含所有可以被发送同时依然停留在状态 $s$ 的报文；
   - M3: 其余部分

   因此在第一阶段，根据选择的 `target_state_id` 选择所有 `state_sequece` 最后一个 `state id == target_state_id` 的region 作为 M2 的范围。

   `target_state_id` 在 main 函数的死循环中由 `choose_target_state` 选出。

   选出 M2 的regions之后，将对应的消息报文**连同前一个消息报文（如果有的话）**读到一个 buffer 作为潜在的变异buffer。

2. 计算 `queue_cur` 的当前表现分数（猜测需要在变异之后进行对比)

3. 裁剪测试用例，基于二分法，在裁剪之后运行测试用例，检查执行路径是否发生变化。若没有变化，则可以直接裁剪。

   裁剪的过程是以块为基本单位进行的，每次尝试拿掉一个块，检查执行路径是否发生变化。

   块的大小在外层循环中每次除半。

4. 翻转比特：对测试用例 buffer 的每个比特进行一次翻转并运行测试用例。

   如果在运行后发现执行路径发生了变化或者已经遍历完所有比特，则调用 `maybe_add_auto` 将测试用例添加到字典中。

   随后又进行了同时翻转2比特、4比特、1字节、2字节的工作。

5. 1、2、4字节的算数运算，大小端均考虑

6. ...

#### `cull_queue`

1. 创建一个 `temp_v` 临时数组，所有比特置1

2. 遍历 queue，将所有非初始种子的项的 `favored` 置0

3. 遍历共享内存，检查

   1. 存在一个对应的最优样例
   2. 临时数组的对应位为1

   若满足，则

4. 遍历该最优样例的 `trace_mini`，将对应的覆盖区域在 `temp_v` 中置0。

   因此可以看出 `temp_v` 数组用于记录目前能够唯一触发对应区域的样例，如果 `temp_v` 对应的位为1，说明之前已经有样例可以触发该区域，则不需要将当前样例置为 favored，否则需要设置 favored。

5. `pending_favored`...

#### `update_bitmap_score`

作用：当发现一条新路径时，调用该函数以判断该路径是否更好；这样做的目的在于找到一个路径的最小集合，该集合可触发已知的 bitmap 的所有点，这样就可以专注于对它们进行 fuzz 以节省时间。

为 bitmap 的每个字节维护一个 `struct queue_entry* toprated[]` 数组，比较路径的优势需要考虑两个因素：

- `q->unique_state_count`
- `fav_factor = q->exec_us * q->len`

两个因素均占优的项可以取代原有项在数组的位置。

#### `update_scores_and_select_next_state`

遍历所有的状态，并更新状态分数。

计算状态分数的代码：

```c
state->score = ceil(1000 * pow(2, -log10(log10(state->fuzzs + 1) * state->selected_times + 1)) * pow(2, log(state->paths_discovered + 1)));
```

对应公式：
$$
S = \lceil 1000 * 2^{-\log_{10}(\log_{10}(F + 1) * T + 1)} * 2^{\ln(P+1)} \rceil
$$
其中

- $S$: 状态分数
- $F$: `state->fuzzs`
- $T$: 状态被选择的次数
- $P$: 状态发现的路径数量

在更新状态分数的过程中，记录所有的状态分数的累积数组。

在所有状态分数的累积的范围内选择一个随机数，选择该随机数落入区域的index对应的状态作为结果。

#### `update_state_aware_variables`

该函数只在 state aware mode 启用的情况下使用，大部分情况下开启 state aware mode。

作用：基于 response buffer 判断响应状态，调用用户提供的 extract 函数提取特征状态码，筛选不同状态码数量赋给 `q->unique_state_count`。

#### `is_state_sequence_interesting`

#### `add_to_queue`

添加一个样例项到队列**头部**，值得注意的项成员：

- `fname`: 样例的种子文件

- `depth`: 种子当前所走过的路径深度，使用 `cur_path+1` 赋值，`cur_path` 只在 `fuzz_one` 进行赋值

  ```c
  cur_path = queue_cur->depth;
  ```

  设想：新添加的 `queue_entry` 都是从 `fuzz_one` 函数中得来，因此 `cur_path` 就代表了当前进行测试的样例深度，在此基础上加一得到新的样例的深度，非常巧妙的设计。

副作用：

- `queued_path++`
- `pending_not_fuzzed++`

之后会读取种子文件到buffer，

- 如果是初始的种子文件，调用 `extract_requests` 函数解析 regions。regions 内容会写入到 out/regions 目录的特定文件中。
- 否则则根据当前的 `kl_messages` 进行转化

#### `construct_kl_messages`

作用：基于 `q->regions` 为界读取种子文件，构造请求消息队列。