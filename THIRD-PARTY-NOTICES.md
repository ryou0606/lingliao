# Third-party notices

本仓库中的邻聊 2.5.1 应用源码以根目录 `LICENSE` 中的 MIT 许可证发布，版权持有人为 ryou0606。

下列直接依赖由 npm 安装，不随本仓库源码分发，各自保持原许可证与署名。本仓库的 MIT 许可不对这些第三方组件重新授权。

| 包 | 锁定版本 | 许可证 |
| --- | --- | --- |
| `@httptoolkit/httpolyglot` | 3.1.0 | MIT |
| `express` | 5.2.1 | MIT |
| `multer` | 2.5.0 | MIT |
| `ws` | 8.21.3 | MIT |

传递依赖以 `package-lock.json` 为准。执行 `npm ci` 之后，各包的许可证文件在 `node_modules/<包名>` 中。
