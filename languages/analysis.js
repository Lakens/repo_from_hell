const fs = require('fs');
const rows = fs.readFileSync('../data/small.csv', 'utf8').split('\n');
console.log(rows.length);
