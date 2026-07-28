import re
file_path = 'frontend/assets/index-v89ZaCto.js'
with open(file_path, 'r', encoding='utf-8') as f:
    code = f.read()

target = 'nodeTypes:TQ,onNodeClick:S,fitView:!0'
replacement = 'nodeTypes:TQ,onNodeClick:S,onKeyDown:b=>{if(b.key=="Backspace"||b.key=="Delete"){const s=l.filter(n=>n.selected).map(n=>n.id);if(s.length){u(prev=>prev.filter(n=>!s.includes(n.id)));m(prev=>prev.filter(e=>!s.includes(e.source)&&!s.includes(e.target)))}}},fitView:!0'

if target in code:
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(code.replace(target, replacement))
    print('Patched successfully!')
else:
    print('Target string not found')
