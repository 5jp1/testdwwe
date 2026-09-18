const fs = require('fs');
let code = fs.readFileSync('chat.php', 'utf8');

code = code.replace(/top:\$\{ov\.y\|\|0\}px; left:\$\{ov\.x\|\|0\}px/g, 'top:${ov.y||0}%; left:${ov.x||0}%');

code = code.replace(/img\.style\.left = `\$\{x \|\| 0\}px`;/g, 'img.style.left = `${x || 0}%`;');
code = code.replace(/img\.style\.top = `\$\{y \|\| 0\}px`;/g, 'img.style.top = `${y || 0}%`;');

// Self profile avatar (line 512 approx)
code = code.replace(
  /'<img src="\.'\+htmlspecialchars\(\$ov\['url'\]\)\+'" style="position:absolute; width:80px; height:80px; top:calc\(50% - 40px \+ '\.\$y\.'px\); left:calc\(50% - 40px \+ '\.\$x\.'px\); transform:scale\('\.\$s\.'\); pointer-events:none; z-index:10; object-fit:contain;">'/,
  '\'<img src="\'.htmlspecialchars($ov[\'url\']).\'" style="position:absolute; width:100%; height:100%; top:\'.($y).\'%; left:\'.($x).\'%; transform:scale(\'.$s.\'); pointer-events:none; z-index:10; object-fit:contain;">\''
);

fs.writeFileSync('chat.php', code);
console.log('done');
