# PyQt6 Layout Migration Guide
## From Fixed Geometry to Dynamic Layouts

This guide provides a comprehensive approach to migrating your PyQt6 application from fixed positioning to dynamic layout managers.

## 🎯 **Overview**

### **Before (Fixed Geometry)**
```python
# Fixed positioning - NOT responsive
button.setGeometry(100, 200, 150, 50)
button.move(x, y)
widget.resize(width, height)
```

### **After (Dynamic Layouts)**
```python
# Layout-based - Responsive and adaptive
layout = QVBoxLayout()
layout.addWidget(button)
widget.setLayout(layout)
```

## 📋 **Migration Steps**

### **Step 1: Analyze Current Structure**

1. **Identify Fixed Elements**
   - Find all `.setGeometry()` calls
   - Locate `.move()` and `.resize()` usage
   - Note `resizeEvent()` scaling logic

2. **Group Related Elements**
   - Identify logical groupings (header, sidebar, content, footer)
   - Determine parent-child relationships
   - Plan layout hierarchy

### **Step 2: Choose Layout Managers**

| Layout Type | Use Case | Example |
|-------------|----------|---------|
| `QVBoxLayout` | Vertical stacking | Navigation menus, form fields |
| `QHBoxLayout` | Horizontal arrangement | Toolbars, button groups |
| `QGridLayout` | Grid-based positioning | Forms, calculator layouts |
| `QFormLayout` | Label-field pairs | Settings, input forms |
| `QStackedLayout` | Overlapping widgets | Tab content, wizard pages |

### **Step 3: Create Layout Hierarchy**

```python
# Example: Main window structure
main_layout = QHBoxLayout()

# Left panel (navigation)
nav_panel = QVBoxLayout()
nav_panel.addWidget(title_label)
nav_panel.addWidget(button1)
nav_panel.addWidget(button2)
nav_panel.addStretch()  # Push content to top

# Right panel (content)
content_panel = QVBoxLayout()
content_panel.addWidget(header)
content_panel.addWidget(main_area, 1)  # Stretch factor
content_panel.addWidget(status_bar)

# Combine panels
main_layout.addLayout(nav_panel, 0)      # Fixed width
main_layout.addLayout(content_panel, 1)  # Expandable
```

## 🔧 **Key Concepts**

### **Layout Properties**

1. **Stretch Factors**
   ```python
   layout.addWidget(widget, stretch_factor)
   # 0 = minimum size, 1+ = proportional expansion
   ```

2. **Size Policies**
   ```python
   widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
   # Horizontal: Expanding, Vertical: Fixed
   ```

3. **Margins and Spacing**
   ```python
   layout.setContentsMargins(left, top, right, bottom)
   layout.setSpacing(pixels)
   ```

### **Responsive Design Patterns**

1. **Flexible Containers**
   ```python
   # Use QFrame as containers
   container = QFrame()
   container.setStyleSheet("QFrame { border: 1px solid #ccc; }")
   layout = QVBoxLayout(container)
   ```

2. **Minimum/Maximum Sizes**
   ```python
   widget.setMinimumSize(QSize(200, 100))
   widget.setMaximumSize(QSize(800, 600))
   ```

3. **Aspect Ratio Maintenance**
   ```python
   widget.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
   widget.setMinimumSize(QSize(400, 300))  # 4:3 ratio
   ```

## 🎨 **Styling for Layouts**

### **CSS-like Styling**
```python
widget.setStyleSheet("""
    QFrame {
        background-color: rgba(0, 0, 0, 100);
        border-radius: 10px;
        border: 1px solid rgba(100, 200, 255, 50);
    }
    QPushButton {
        min-height: 40px;
        padding: 8px 16px;
    }
""")
```

### **Responsive Breakpoints**
```python
def resizeEvent(self, event):
    super().resizeEvent(event)
    width = self.width()
    
    if width < 800:
        # Mobile layout
        self.sidebar.setVisible(False)
        self.main_layout.setDirection(QBoxLayout.Direction.TopToBottom)
    else:
        # Desktop layout
        self.sidebar.setVisible(True)
        self.main_layout.setDirection(QBoxLayout.Direction.LeftToRight)
```

## 🔄 **Migration Examples**

### **Example 1: Button Panel**

**Before (Fixed):**
```python
def setup_buttons(self):
    self.button1.setGeometry(50, 100, 100, 40)
    self.button2.setGeometry(50, 150, 100, 40)
    self.button3.setGeometry(50, 200, 100, 40)

def resizeEvent(self, event):
    # Complex scaling logic
    scale = self.width() / 800
    self.button1.setGeometry(int(50*scale), int(100*scale), 
                           int(100*scale), int(40*scale))
    # ... repeat for each button
```

**After (Layout):**
```python
def setup_buttons(self):
    layout = QVBoxLayout()
    layout.setSpacing(10)
    layout.addWidget(self.button1)
    layout.addWidget(self.button2)
    layout.addWidget(self.button3)
    layout.addStretch()
    
    container = QFrame()
    container.setLayout(layout)
    container.setFixedWidth(150)  # Optional: fixed width
```

### **Example 2: Input Form**

**Before (Fixed):**
```python
self.label1.setGeometry(20, 50, 100, 30)
self.input1.setGeometry(130, 50, 200, 30)
self.label2.setGeometry(20, 90, 100, 30)
self.input2.setGeometry(130, 90, 200, 30)
```

**After (Layout):**
```python
form_layout = QFormLayout()
form_layout.addRow("Label 1:", self.input1)
form_layout.addRow("Label 2:", self.input2)

# Or using grid layout
grid_layout = QGridLayout()
grid_layout.addWidget(QLabel("Label 1:"), 0, 0)
grid_layout.addWidget(self.input1, 0, 1)
grid_layout.addWidget(QLabel("Label 2:"), 1, 0)
grid_layout.addWidget(self.input2, 1, 1)
```

## 🚀 **Advanced Features**

### **Custom Layout Managers**
```python
class FlowLayout(QLayout):
    """Custom layout that flows widgets like text"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.item_list = []
    
    def addItem(self, item):
        self.item_list.append(item)
    
    def sizeHint(self):
        return self.minimumSize()
    
    def doLayout(self, rect, testOnly):
        # Custom layout logic here
        pass
```

### **Animation Support**
```python
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve

def animate_resize(self, widget, start_size, end_size):
    self.animation = QPropertyAnimation(widget, b"size")
    self.animation.setDuration(300)
    self.animation.setStartValue(start_size)
    self.animation.setEndValue(end_size)
    self.animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    self.animation.start()
```

## 📱 **Accessibility Improvements**

### **Keyboard Navigation**
```python
# Set tab order
self.setTabOrder(self.input1, self.input2)
self.setTabOrder(self.input2, self.button1)

# Focus policies
widget.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
```

### **Screen Reader Support**
```python
# Accessible names and descriptions
widget.setAccessibleName("Main navigation button")
widget.setAccessibleDescription("Click to open the main navigation menu")

# Keyboard shortcuts
action = QAction("&Save", self)
action.setShortcut(QKeySequence("Ctrl+S"))
```

## 🎯 **Best Practices**

### **1. Layout Hierarchy**
- Keep layouts shallow (max 3-4 levels deep)
- Use container widgets (QFrame, QWidget) to group related elements
- Separate concerns (navigation, content, status)

### **2. Responsive Design**
- Use stretch factors appropriately
- Set minimum/maximum sizes where needed
- Test on different screen sizes

### **3. Performance**
- Avoid excessive nesting
- Use `setVisible(False)` instead of removing widgets
- Cache layout calculations when possible

### **4. Maintainability**
- Create reusable layout components
- Use descriptive names for layouts
- Document complex layout logic

## 🔍 **Testing Your Migration**

### **Checklist**
- [ ] All widgets visible at different window sizes
- [ ] No overlapping elements
- [ ] Proper tab order
- [ ] Keyboard shortcuts work
- [ ] Responsive behavior on resize
- [ ] Consistent spacing and alignment
- [ ] Accessibility features functional

### **Test Scenarios**
1. **Minimum window size** - All elements still accessible
2. **Maximum window size** - No excessive stretching
3. **Aspect ratio changes** - Layout adapts properly
4. **Font size changes** - Text remains readable
5. **High DPI displays** - Scaling works correctly

## 📚 **Resources**

### **PyQt6 Documentation**
- [Layout Management](https://doc.qt.io/qtforpython/overviews/layout.html)
- [Size Policies](https://doc.qt.io/qtforpython/PySide6/QtWidgets/QSizePolicy.html)
- [Responsive Design](https://doc.qt.io/qtforpython/overviews/responsive.html)

### **Tools**
- Qt Designer for visual layout creation
- Qt Style Sheets for responsive styling
- Accessibility Inspector for testing

## 🎉 **Benefits of Migration**

### **User Experience**
- ✅ Responsive design works on all screen sizes
- ✅ Better accessibility support
- ✅ Consistent spacing and alignment
- ✅ Professional appearance

### **Developer Experience**
- ✅ Easier maintenance and updates
- ✅ Less complex resize handling
- ✅ Better code organization
- ✅ Reduced bugs related to positioning

### **Future-Proofing**
- ✅ Adapts to new screen sizes automatically
- ✅ Easier to add new features
- ✅ Better internationalization support
- ✅ Modern UI/UX standards compliance

---

**Remember:** Migration is an iterative process. Start with one page/component, test thoroughly, then move to the next. The investment in layout-based design pays off in maintainability and user experience!