# PyPI 发布配置说明

## 问题：OIDC Token 无效

如果遇到以下错误：
```
Invalid API Token: OIDC scoped token is not valid for project 'ic-candid-parser'
```

这意味着 PyPI 上的项目还没有创建，或者 Trusted Publisher 配置不正确。

## 解决方案

### 方案 1：手动在 PyPI 上创建项目（推荐）

1. 访问 https://pypi.org/manage/account/
2. 登录你的 PyPI 账户
3. 访问 https://pypi.org/manage/projects/
4. 点击 "Add new project"
5. 输入项目名：`ic-candid-parser`
6. 创建项目

### 方案 2：配置 Trusted Publisher

1. 访问 https://pypi.org/manage/account/
2. 登录你的 PyPI 账户
3. 访问 https://pypi.org/manage/account/publishing/
4. 点击 "Add a new pending publisher"
5. 配置如下：
   - **PyPI project name**: `ic-candid-parser`
   - **Owner**: `eliezhao` (你的 GitHub 用户名)
   - **Repository name**: `icp-py-core`
   - **Workflow filename**: `.github/workflows/release.yml`
   - **Environment name**: `pypi` (必须与 workflow 中的 environment 名称匹配)
   - **Specify version**: 留空（允许所有版本）

6. 点击 "Add"

### 方案 3：使用 API Token（临时方案）

如果 Trusted Publisher 配置有问题，可以临时使用 API Token：

1. 访问 https://pypi.org/manage/account/token/
2. 创建一个新的 API Token
3. 在 GitHub 仓库的 Settings → Secrets and variables → Actions 中添加：
   - Name: `PYPI_API_TOKEN`
   - Value: 你的 API Token
4. 修改 workflow 文件，使用 API Token 而不是 OIDC

## 验证配置

配置完成后，重新运行 GitHub Actions 工作流。如果仍然失败，请检查：

1. GitHub Environment `pypi` 是否已创建（Settings → Environments）
2. Trusted Publisher 配置中的项目名、仓库名、工作流文件名是否完全匹配
3. Environment 名称是否与 workflow 中的 `environment: pypi` 匹配

## 注意事项

- PyPI 项目名是 `ic-candid-parser`（带连字符）
- 安装时的包名是 `ic_candid_parser`（下划线），pip 会自动处理转换
- 主包的依赖配置使用 `ic_candid_parser>=0.1.0`，这是正确的
