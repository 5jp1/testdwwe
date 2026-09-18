const fs = require('fs');
const content = fs.readFileSync('chat.php', 'utf8');
const scriptMatch = content.match(/<script>([\s\S]*?)<\/script>/);
if (scriptMatch) {
  try {
    new Function(scriptMatch[1]);
    console.log("Syntax OK");
  } catch (e) {
    console.error("Syntax Error: " + e.message);
  }
}
