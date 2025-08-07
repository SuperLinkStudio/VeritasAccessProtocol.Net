# VeritasAccessProtocol.Net

VeritasAccessProtocol 的 .Net 实现

## 核心库

### VeritasAccessProtocol.TimeBasedDeterministicToken

TimeBasedDeterministicToken 是一种结合时间戳、密钥和哈希处理的算法，用于：

- 辅助验证资源服务器和客户端身份
- 抵抗重放攻击
- 保护用户数据交互安全

#### `TimeBasedDeterministicTokenGenerator`

TDT 生成器。

##### 构造函数

```csharp
public TimeBasedDeterministicTokenGenerator(string secret);
```

| 参数     | 描述         |
| -------- | ------------ |
| `secret` | TDT 共享密钥 |

##### `Generate` 方法

```csharp
public byte[] Generate(long timestamp, int resultLength = 256);

public byte[] Generate(int resultLength = 256);
```

| 参数           | 描述                           |
| -------------- | ------------------------------ |
| `timestamp`    | 时间戳（可选）                 |
| `resultLength` | 生成的 TDT 长度（默认 256 位） |

#### `TimeBasedDeterministicTokenValidator`

TDT 验证器

##### 构造函数

```csharp
public TimeBasedDeterministicTokenValidator(string secret)
```

| 参数     | 描述         |
| -------- | ------------ |
| `secret` | TDT 共享密钥 |

##### `Validate` 方法

```csharp
public bool Validate(long timestamp, byte[] token, int resultLength = 256);

public bool Validate(long timestamp, byte[] token);
```

| 参数           | 描述                           |
| -------------- | ------------------------------ |
| `timestamp`    | 时间戳（可选）                 |
| `token`        | 需验证的 TDT 令牌              |
| `resultLength` | 生成的 TDT 长度（默认 256 位） |
