# APNG 归档审计服务

显微成像平台在归档动态 PNG 前，用本服务对 APNG 原始字节做**严格结构审计**：
只有当画布（IHDR）、帧控制块（fcTL）与压缩载荷（IDAT/fdAT）属于同一条
完整、连续、未截断的动画时才放行，避免播放器容错掩盖截断、乱序或越界帧。

仅使用 Python 3.11 标准库，无第三方运行时依赖。

## 接口

### `POST /api/apng/audit`

- 请求：`Content-Type: image/apng`，Body 为不超过 **8 MiB** 的原始字节
- 成功：`200 OK`
- 结构不成立：`422 Unprocessable Entity`，响应仅含错误说明与可定位的
  **块序号**（`chunk`，从 0 开始，IHDR 为 0），**不输出任何部分帧清单**

校验规则：

1. PNG 签名正确；首块为合法 IHDR（非零尺寸、合法位深/色彩类型/方法）；
   末块为空 IEND，IEND 后不得残留任何字节。
2. 逐块校验长度边界与 CRC（任何截断、声明长度越界、CRC 不符立即拒绝）。
3. 必须是 APNG：恰有一个 acTL，位于首个 fcTL 之前；`num_frames` 非零且
   ≤ 512；索引色图像须携带位置合法的 PLTE。
4. 首个 fcTL 必须位于首个 IDAT 之前。
5. fcTL 与 fdAT 的 `sequence_number` 必须从 0 开始**严格连续**（无重复、
   无跳号）。
6. 首帧必须由一个或多个**连续 IDAT** 组成；后续每帧必须由至少一个
   **连续 fdAT** 组成；载荷不得为空。
7. 每个帧矩形（x、y、width、height）不得越出 IHDR 画布；
   `dispose_op` / `blend_op` 取值合法。
8. 延时 `delay_den` 为 0 时按 **100** 解释（规范化延时）。

成功响应示例（节选）：

```json
{
  "canvas": {"width": 16, "height": 16, "bit_depth": 8, "color_type": 6},
  "num_frames": 3,
  "num_plays": 3,
  "infinite": false,
  "frames": [
    {
      "index": 0,
      "rect": {"x": 0, "y": 0, "width": 8, "height": 8},
      "delay": {"num": 1, "den": 100, "den_was_zero": false, "seconds": 0.01},
      "dispose": "none",
      "blend": "source",
      "compressed_data_sha256": "d65a905a…62a5"
    }
  ]
}
```

`frames` 按流顺序排列；`compressed_data_sha256` 是该帧全部连续载荷块数据
拼接后的 SHA-256（首帧为 IDAT 拼接，其余为 fdAT 去掉 4 字节序号后拼接），
保证归档摘要稳定。`num_plays` 为 0 时 `infinite=true`。

错误响应示例：

```json
{"error": "sequence number discontinuity at fcTL: expected 1, found 7", "chunk": 4}
```

其他状态码：`415`（Content-Type 非 image/apng）、`413`（超过 8 MiB）、
`411`（缺少 Content-Length）、`400`（请求体短于声明长度）。

### `GET /health`

返回 `200 {"status":"ok"}`，供容器健康检查使用。

## 运行

宿主机端口可通过 `HOST_PORT` 配置（默认 8080）：

```bash
docker compose up --build web
HOST_PORT=9090 docker compose up --build web     # 映射到宿主机 9090
curl -X POST http://localhost:${HOST_PORT:-8080}/api/apng/audit \
     -H 'Content-Type: image/apng' --data-binary @animation.apng
```

## 一次性验收服务 verify

`verify` 是一次性服务：清洁启动后它等待 web 健康，然后依次

1. 运行全部单元/集成测试（`tests/`，45 个用例）；
2. 对应用模块与自身做字节码“构建”检查；
3. 提交一份**合法动画**，断言 200、有序帧清单、规范化延时与各帧
   SHA-256 与独立解析结果一致；
4. 提交一份**序号损坏动画**，断言 422、响应带块序号且无部分帧清单。

它以退出码汇总结果（全过 0，任一失败 1），随后自行退出：

```bash
docker compose up --build verify
docker compose logs verify      # 查看每个步骤的 PASS/FAIL
docker compose rm -f verify     # 清理已退出的一次性容器
```

## 本地开发（无需容器）

```bash
python3 -m unittest discover -s tests -v   # 运行测试
PORT=8080 python3 -m app.server            # 启动服务
SERVICE_URL=http://127.0.0.1:8080 python3 verify.py
```

## 项目结构

```
app/apng.py        严格 APNG 结构解析器（签名/IHDR/CRC/语法/序号/矩形/载荷）
app/apng_build.py  测试与验收使用的最小 APNG 构造器（可精确制造各类损坏）
app/server.py      POST /api/apng/audit 与 GET /health（标准库 HTTP）
tests/             解析器与 HTTP 端到端测试
verify.py          一次性验收脚本（测试 + 构建 + 合法/损坏提交，退出码汇总）
Dockerfile         python:3.11-slim，含 HEALTHCHECK
docker-compose.yml web（可配置宿主端口 + 健康检查）与 verify（一次性）
```
