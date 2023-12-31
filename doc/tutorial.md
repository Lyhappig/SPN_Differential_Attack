## 建议

建议在typora下阅读

## 密码结构

将16位数据块分解为4个 4-bit 子块。每个子块形成一个 4×4 S盒的输入（用4输入位和4输出位替换），由4个输入位表示的整数进行索引。S盒最基本的性质是它是一个非线性映射，即输出位不能表示为对输入位的线性操作。

在该密码体系下，所有的S盒都是相同的（从DES的第一个S盒的第一行取得的），S盒的结构和代换规则分别如下图所示：

<img src="https://cdn.jsdelivr.net/gh/Lyhappig/images/CtPh6Dp9R8B1UTa.png" alt="差分分析-pic5.png" style="zoom: 50%;" />

![差分分析-pic2.png](https://cdn.jsdelivr.net/gh/Lyhappig/images/PzMDmLGRVFIawEk.png)

P置换如下图所示，最后一轮没有置换：

![差分分析-pic3.png](https://cdn.jsdelivr.net/gh/Lyhappig/images/7stacLrwP5CRdzQ.png)

密码体系结构如下图所示：

<img src="https://cdn.jsdelivr.net/gh/Lyhappig/images/TsVGH1P7JkOyRCe.png" alt="差分分析-pic4.png" style="zoom: 50%;" />

## 差分分析

为了构建高概率的差分特征，检查单个S盒的属性，并使用这些属性来确定完整的差分特征。具体地说，考虑S盒的输入和输出差分，以确定一个高概率差分。结合一轮到下一轮的S盒差分对，可以得出一轮的非零输出差分对应于下一轮的非零输入差分，使我们能够找到由明文差分和最后一轮输入差分组成的高概率差分。

### S盒的差分分布表

考虑 4×4 S盒的表示，输入 $X=[X_1X_2X_3X_4]$，输出 $Y=[Y_1Y_2Y_3Y_4]$。给出 $\Delta X$ 可以通过考虑输入对 $(X',X'')$ 来得出，因此 $X'\oplus X''=\Delta X$。对于一个 4×4 的S盒，我们只需要考虑 $X'$ 的所有16个值， $\Delta X$ 的值可以约束 $X''$ 的值，即为 $X''=X'\oplus \Delta X$。

考虑到上述给出密码的S盒，我们可以推导出每个输入对的 $\Delta Y$ 的结果值 $(X',X''=X' \oplus \Delta X)$。例如，$X,Y$ 的二进制值和相应的 $\Delta Y$ 对给定输入对 $(X,X⊕∆X)$ 如下表所示，其中 $\Delta X$ 值为1011（十六进制B）、1000（十六进制8）和0100（十六进制4）。如果S盒是"理想的"，那么差分对值的出现次数都为1，以表示给定 $∆X$ 的特定 $∆Y$ 值的出现概率为 $\frac{1}{16}$。事实证明，这样一个"理想的"S盒是不可能的。

<img src="https://cdn.jsdelivr.net/gh/Lyhappig/images/NZvqrudgRQYfTBm.png" alt="差分分析-pic6.png" style="zoom:40%;" />

我们可以在差分分布表中将S盒的完整数据制成表格，其中行表示 $∆X$ 值（以十六进制为单位），列表示 $∆Y$ 值（以十六进制为单位），表中元素代表给定 $\Delta X$ 后 $\Delta Y$ 的出现次数。该密码体系中S盒的差分分布表如下表所示。

<img src="https://cdn.jsdelivr.net/gh/Lyhappig/images/Q2sSYRk3VjpFneJ.png" alt="差分分析-pic7.png" style="zoom:40%;" />

从差分分布表可以看出几个一般性质。首先，一行中所有元素的和是 $2^n=16$，这与输出差分的位数有关；类似地，任意的列的和为 $2^n=16$，这与输入差分的位数有关。此外，所有的元素值都是偶数，这一现象是因为表示为 $(X',X'')$ 的一对输入（或输出）值与这对 $(X''，X')$ 具有相同的 $∆X$ 值，因为 $∆X=X'\oplus X''=X'' \oplus X'$。此外，对于S盒的一对一映射，$∆X=0$ 的输入差分必定导致 $∆Y=0$ 的输出差分。因此，表的左上角的值为 $2^n=16$ 和第一行与第一列中的所有其他值都为0。

考虑明文进入S盒前需要进行加密，根据异或的性质 $\Delta X = X' \oplus X'' = (X' \oplus K) \oplus (X'' \oplus K)$，可以得出加密后的S盒与不加密的S盒具有相同的输入差分。

### 差分特征

#### 活跃S盒

具有非零输入差分的S盒称为活跃S盒。一般来说，活跃S盒的差分概率越大，整个密码系统的差分概率就越大；活跃S盒越少，整个密码系统的差分概率就越大。

#### 构造差分特征

寻找合适的输入差分，根据S盒的差分分布不均匀性，构造活跃S盒的数量尽可能的少，概率尽可能大的差分特征，使得破解密钥部分比特的复杂度尽可能的低。

构造一个涉及 $S_{12}、S_{23}、S_{32}$ 和 $S_{33}$ 的高概率差分特征，如下图所示。该图说明了非零差分的影响，突出了可能被认为是活跃的S盒(即它是一个非零差分)。使用的四个S盒的差分对如下：

- $S_{12}$：$\Delta X = B \rightarrow \Delta Y = 2$，概率为 $8/16$
- $S_{23}$：$\Delta X = 4 \rightarrow \Delta Y = 6$，概率为 $6/16$
- $S_{32}$：$\Delta X = 2 \rightarrow \Delta Y = 5$，概率为 $6/16$
- $S_{33}$：$\Delta X = 2 \rightarrow \Delta Y = 5$，概率为 $6/16$

其他所有S盒的的输入差分为0，对应输出差分也为0。记如下符号：$\Delta P$ 代表明文差分；$\Delta U_i,1 \leq i \leq 4$ 代表第 $i$ 个S盒的输入差分；$\Delta V_i,1 \leq i \leq 4$ 代表第 $i$ 个S盒的输出差分；$K_i,1 \leq i\leq 4$ 代表第 $i$ 轮加密的轮密钥；$\Delta U_{i,j}, \Delta V_{i,j},K_{i,j},1 \leq i \leq 4,1 \leq j \leq 16$ 分别代表第 $i$ 轮输入差分、输出差分、轮密钥的第 $j$ 位。

<img src="https://cdn.jsdelivr.net/gh/Lyhappig/images/KU9nwLTuFoDPE6B.png" alt="差分分析-pic8.png" style="zoom:50%;" />

假设S盒之间互相独立，则给定明文差分 $\Delta P = 0000~1011~0000~0000$ ，第三轮S盒输出差分为 $\Delta V_3 = 0000~0101~0101~0000$，前三轮差分特征的概率为 $\frac{8}{16} * \frac{6}{16} * (\frac{6}{16})^2 = \frac{27}{1024}$。

使用许多满足明文差分的明文对，符合该差分特征的称为正确对，否则为错误对。通过构造前三轮差分特征来攻击第四轮子密钥，该方法称为 $R-1$ 轮差分特征。

### 获得子密钥部分比特

将最后一轮受活跃S盒影响的子密钥部分位称为目标部分子密钥。

获得目标部分子密钥的主要过程为：

1. 尝试枚举目标部分子密钥的所有可能，对所有可能的部分子密钥设置一个计数系统。
2. 根据第四轮输出差分过滤部分错误对。
3. 枚举符合明文差分的明文对，通过对最后一轮得出的密文进行部分解密，与最后一轮S盒的输入差分进行检验，若相同则为正确对，对应计数器加一，否则为错误对。
4. 计数结束后具有最大计数数值的部分子密钥表示为目标部分子密钥的正确值。

我们选取的差分特征影响了最后一轮对S型盒 $S_{42}$ 和 $S_{44}$ 的输入。对于每个密文对，我们将尝试 $[K_{5,5}...K_{5,8}, K_{5,13}...K_{5,16}]$ 的所有256个值。对于每个部分子密钥，当由部分解密决定的最后一轮的输入差分与 $[\Delta U_{4,5}...\Delta U_{4,8},\Delta U_{4,13}…\Delta U_{4,16}]$ 的值相同时，将增加计数，最大的计数被认为是目标部分子密钥的正确值。

**注意不需要对每个密文对都执行部分解密**。由于最后一轮的输入差分只影响2个S盒，当差分特征发生时 （即对于正确对），$S_{41}$ 和 $S_{43}$ 对应的密文位差分必须为零。因此我们可以通过判断密文的零差分块是否由正确的S盒输出来过滤掉许多错误的对，在这些情况下，由于密文对不能对应于一个正确对，因此没有必要检查 $[∆U_{4,5}...∆U_{4,8},∆U_{4,13}...∆U_{4,16}]$。

这是可行的，因为它假设正确的部分子密钥将导致最后一轮差分的频率等同于差分特征期望（因为该差分特征具有很高的发生概率）。当发生错误对时，即使使用了正确的子密钥进行解密，也不会导致对应计数器增加（即使有可能，但是概率特别低）。

通过生成5000个明文/密文对，正如期望的那样，最大的计数值 $count$ 即为正确的子密钥。概率 $prob = count / 5000$ 最接近 $27/1024 \approx 0.02637$

### 复杂度分析

对于所选择明文对的数量 $N_D$，满足 $N_D \approx c / p$，其中 $c$ 是常数，$p$ 是差分特征的概率。这个式子不难发现是正确的，它表示了在平均的情况下每 $1 / p$ 对的明文对中就会有一个正确对，使用它的小倍数 $c$ 数量的明文对来攻击是合理的。

其中 $p$ 是 $R-1$ 轮差分概率的乘积，每一轮的差分概率等于该轮次中活跃 $S$ 盒对应差分分布表中概率的乘积

$p = \prod_\limits{i=1}^{\gamma} \beta_i$，其中活跃 $S$ 盒的数量用 $\gamma$ 表示。