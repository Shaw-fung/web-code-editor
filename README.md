# Web代码编辑器

一个功能强大的在线代码编辑器，支持多种编程语言，提供语法高亮、主题切换、代码分享等功能。

## 功能介绍

- **代码编辑**：支持多种编程语言的语法高亮和代码提示
- **主题切换**：提供明亮和暗黑两种主题模式，保护开发者视力
- **查找替换**：支持文本查找和替换功能，提高代码编辑效率
- **用户系统**：支持用户注册、登录和个人中心管理
- **响应式设计**：适配不同屏幕尺寸，提供良好的移动端体验
- **实时提示**：操作反馈通过右下角弹出的提示消息展示，不遮挡编辑区域
- **实时保存**：登录用户每次更改都会实时保存

## 功能特色

- **现代化界面**：简洁美观的用户界面，专注于代码编辑体验
- **高效编辑**：支持多种快捷键操作，提高开发效率
- **安全可靠**：采用安全的用户认证机制，保护用户数据
- **可扩展**：模块化设计，便于功能扩展和定制
- **性能优化**：优化的代码结构和资源加载，确保流畅的编辑体验

## 技术栈

### 后端
- **Flask**：轻量级Python Web框架
- **SQLAlchemy**：ORM数据库框架
- **Flask-Login**：用户认证管理
- **Flask-WTF**：表单处理和验证
- **Passlib**：密码安全哈希

### 前端
- **HTML5/CSS3**：页面结构和样式
- **JavaScript**：交互逻辑实现
- **CodeMirror**：代码编辑器核心
- **Font Awesome**：图标库

### 数据库
- **SQLite**：默认轻量级数据库，支持其他关系型数据库

## 搭建步骤

### 1. 克隆项目

```bash
git clone https://github.com/Shaw-Fung/web-code-editor.git
cd web-code-editor
```

### 2. 创建虚拟环境（可选但推荐）

```bash
# 使用venv创建虚拟环境
python3 -m venv venv

# 激活虚拟环境
# macOS/Linux
source venv/bin/activate
# Windows
venv\Scripts\activate
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量

创建`.env`文件，添加必要的环境变量：

```env
# 数据库配置
DATABASE_URL=sqlite:///app.db

# 秘密密钥，用于加密会话
SECRET_KEY=your-secret-key-here

# 调试模式
DEBUG=True
```

### 5. 初始化数据库

```bash
python -c "from app import db; db.create_all()"
```

### 6. 启动应用

```bash
flask run
```

应用将在`http://localhost:5000`启动。

## 使用说明

### 基本操作

1. **打开编辑器**：访问应用首页即可看到代码编辑区域
2. **选择语言**：在顶部工具栏选择编程语言
3. **编辑代码**：在编辑区域输入或粘贴代码
4. **切换主题**：点击右上角主题切换按钮
5. **查找替换**：使用快捷键`Ctrl+F`查找，`Ctrl+H`替换
6. **保存代码**：登录后可以保存代码

### 用户功能

1. **注册**：点击右上角注册按钮，填写信息创建账号
2. **登录**：使用注册的账号登录
3. **个人中心**：登录后可以管理个人信息和保存的代码

## 常见问题

### Q: 注册功能无法使用？
A: 管理员可能关闭了注册功能。请联系管理员获取账号或开启注册功能。

### Q: 如何切换编辑器主题？
A: 点击右上角的主题切换按钮，可以在明亮和暗黑主题之间切换。

### Q: 支持哪些编程语言？
A: 支持多种常见编程语言，包括但不限于JavaScript、Python、Java、C++、HTML、CSS等。

### Q: 代码保存后在哪里查看？
A: 登录后，可以查看和管理所有保存的代码。

## 快捷键

- **Ctrl+F**：打开查找对话框
- **Ctrl+H**：打开替换对话框
- **Ctrl+S**：保存代码
- **Ctrl+Z**：撤销
- **Ctrl+Y**：重做
- **Ctrl+A**：全选
- **Ctrl+C**：复制
- **Ctrl+V**：粘贴
- **Ctrl+X**：剪切

## 项目结构

```
web-code-editor/
├── app.py              # 应用主入口
├── requirements.txt    # 项目依赖
├── templates/          # HTML模板
│   └── index.html      # 主页面
├── static/             # 静态资源
│   ├── css/            # CSS样式
│   │   └── style.css   # 主样式文件
│   ├── js/             # JavaScript文件
│   │   ├── editor.js   # 编辑器核心逻辑
│   │   └── personal_center.js # 个人中心逻辑
│   └── images/         # 图片资源
└── README.md           # 项目说明文档
```

## 贡献指南

1. Fork项目
2. 创建功能分支：`git checkout -b feature/AmazingFeature`
3. 提交更改：`git commit -m 'Add some AmazingFeature'`
4. 推送到分支：`git push origin feature/AmazingFeature`
5. 提交Pull Request

## 许可证

本项目采用MIT许可证。详见[LICENSE](LICENSE)文件。

## 联系方式

- 项目地址：https://github.com/Shaw-Fung/web-code-editor
- 作者：Shaw-Fung

---

**感谢使用Web代码编辑器！** 如果您有任何问题或建议，欢迎提交Issue或Pull Request。