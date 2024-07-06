const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion } = require('mongodb');

const path = require('path');
const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

const uri = "mongodb+srv://sqlinject125:bF3eRXcQ2N27skcR@cluster0.sngww8x.mongodb.net/?retryWrites=true&w=majority";

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

// Provide SQL injection patterns and suggestions dynamically
const providedPatterns = [

  
  { pattern: /(['"])\s*OR\s*('|")/i, suggestion: 'Avoid using SQL injection patterns like \' OR \'' },
  { pattern: /1\s*=\s*1/i, suggestion: 'Avoid using SQL injection patterns like \'1=1\'' },
  { pattern: /admin\s*'\s*#/i, suggestion: 'Avoid using SQL injection patterns like \'admin\'#\'' },
  { pattern: /admin\s*'\s*\/\*/i, suggestion: 'Avoid using SQL injection patterns like \'admin\'/*' },
  {pattern:/(<\/?[^>]+>|[\(\)])/g},
  {pattern:/<\/>/},
  {pattern:/admin\s*'\s*--/i,},
 
  {pattern:/\bAND\s+\w+\s*=\s*\w+0#/i},
  {pattern:/\bAND\s+1=0#/i},
  {pattern:/\bAND\s+\w+\s*=\s*\w+\b/i},
  {pattern:/\bAND\s+1=0\b/i},
  {pattern:/admin'\s*or\s*\(\s*'1'\s*=\s*'1'[^a-zA-Z0-9_]/i,},
  {pattern:/admin'\)\s*or\s*\(\s*'1'\s*=\s*'1'\s*--/i},
  {pattern:/admin'\)\s*or\s*\s*'1'\s*=\s*'1/i},
  {pattern:/admin"\s*--/i},
  {pattern:/&/},
  {pattern:/-/},
  {pattern:/\s+or\s+sleep\(5\)/i},

  
  {pattern:/' '/},
  {pattern:/''/},
  {pattern:/\^/},
  {pattern:/AnD\s+SLEEP\(5\)/i},
  {pattern:/\bAND\s+\w+\s*=\s*\w+\s+AND\s+'%'\s*=\s*'/i},
  {pattern:/pg_SLEEP\(5\)/i},
  {pattern:/SLEEP\(5\)\s*=\s*"/i},
  {pattern:/\bAND\s+\w+\s*=\s*\w+\s+AND\s+\(\w+\s*=\s*\w+/i},

  {pattern:/SLEEP\(5\)#/i},
  {pattern:/%'\s*AND\s*8310=8311\s*AND\s*'%'\s*=/i},
  {pattern:/\bAND\s+\d+\s*=\s*\d+\s+AND\s+\(\d+\s*=\s*\d+/i},
  {pattern:/'.*?1=1\s*\/\*\w*\*\/\s*#/i},
  {pattern:/1\*56/},
  {pattern:/\d+\*\d+/},
  {pattern:/\bAND\s+false\b/i},
  {pattern:/\bAND\s+true\b/i},
  {pattern:/\bAND\s+0\b/i},
  {pattern:/\bAND\s+\w+\b/i},
  {pattern:/#\s*\d+/},
  {pattern:/#\s*\w+\s+number/i},
  {pattern:/@@\w+/},
  {pattern:/@\w+/},
  {pattern:/%/},
  {pattern:/\+/},
  {pattern:/\/\*.*?\*\//s},

  {pattern:/\|\|/},
  {pattern:/'.*?'/},
  {pattern:/;/},
  {pattern:/\\\\/},
  {pattern:/\\/},
  {pattern:/\/\// },
  {pattern:/\// },
  {pattern:/"/},
  {pattern:/`/},
  {pattern:/'/},
  {pattern:/,/},






  {pattern:/%'\s*AND\s*8310=8310\s*AND\s*'%'\s*=/i},
  {pattern:/%'\s*AND\s*\d+\s*=\s*\d+\s*AND\s*'%'\s*=/i},
  {pattern:/ORDER\s+BY\s+\d+/i},
  {pattern:/\bORDER\s+BY\s+\d+\s*--/i},
  {pattern:/\bAND\s+\d+\s*=\s*\d+\s+AND\s+\('\d+\s*=\s*\d+/i},

  {pattern:/\bORDER\s+BY\s+\w+\s*#/i},
  {pattern:/waitfor\s+delay\s+'.*?#\s*/i},




  {pattern:/'>'/},

  {pattern:/'<'/},

  
  {pattern:/admin"\s*\/\*/i},
  {pattern:/admin"\)\s*or\s*"\(\s*"1"\s*=\s*"1"/i},
  {pattern:/admin"\)\s*or\s*\(\s*"1"\s*=\s*"1/i},
  {pattern:/admin"\)\s*or\s*\s*"1"\s*=\s*"1/i},
  {pattern:/admin'\)\s*or\s*\(\s*'1'\s*=\s*'1/i},
  {pattern:/1234"\s*AND\s*1=0\s*UNION\s*ALL\s*SELECT\s*"admin",\s*"81dc9bdb52d04dc20036dbd8313ed055"/i},
  {pattern:/(1234|UNION|SELECT)/i}

  // Add more patterns as needed
];

async function run() {



  try {
    await client.connect();
    const database = client.db("sqlinjectionPreventionDB");
    const sqlinjlist = database.collection("sqlinjectionList");
    const storedList=database.collection("storedproclist");


   app.post('/stored-code',async(req,res)=>{

    const { programCodes } = req.body;
    await storedList.insertOne({ programCodes });

  // Regular expressions for detecting patterns
  const preparePattern = /\bprepare\b|\bmysqli_prepare\b/i;
  const bindParamPattern = /\bbind_param\b|\bmysqli_stmt_bind_param\b/i;
  const executePattern = /\bexecute\b|\bmysqli_stmt_execute\b/i;

  // Check for patterns in user input
  const hasPrepare = preparePattern.test(programCodes);
  const hasBindParam = bindParamPattern.test(programCodes);
  const hasExecute = executePattern.test(programCodes);

  // Suggestions array
  const suggestions = [];

  // Check for patterns and add suggestions
  if (!hasPrepare) {
    suggestions.push('Consider using prepare() or mysqli_prepare() for SQL statements.');
  }
  if (!hasBindParam) {
    suggestions.push('Consider using bind_param() or mysqli_stmt_bind_param() for binding parameters.');
  }
  if (!hasExecute) {
    suggestions.push('Consider using execute() or mysqli_stmt_execute() for executing prepared statements.');
  }

  // Respond based on the patterns found
  if (hasPrepare && hasBindParam && hasExecute) {
    res.json({ success: true, message: 'No action needed' });
  } else {
    res.json({
      success: false,
      message: 'Potential security risk detected. Avoid using  direct SQL queries.',
      suggestions
    });
  }

   })

 


   app.post('/save-code', async (req, res) => {
    try {
      const { programCode } = req.body;
      

      // Check for potential SQL injection patterns before saving
      const detectedPattern = checkForSqlInjection(programCode, providedPatterns);
      if (!programCode) {
        return res.status(400).json({
          success: false,
          message: `please enter some input in the input field`,
        });
      }
      if (detectedPattern) {
        return res.status(400).json({
          success: false,
          message: `Potential SQL injection detected. Use Regex : "${detectedPattern.pattern}" to Mitigate SQL Injections.`,
        });
      }
  
      // If no SQL injection pattern detected, save the code in the database
      await sqlinjlist.insertOne({ programCode });
  
      res.json({ success: true, message: 'Code saved successfully, No action needed.' });
    } catch (error) {
      console.error('Error saving code:', error);
      res.status(500).json({ success: false, message: 'Internal server error.' });
    }
  });
  

    app.get('/', (req, res) => {
      res.send('Simple CRUD');
    });






    app.listen(port, () => {
      console.log(`Server is running on port ${port}`);
    });

  } finally {
    // Uncomment the following line if you want to close the connection when the script exits
    // await client.close();
  }
}

function checkForSqlInjection(code, patterns) {
  // Check if the code contains any provided SQL injection patterns
  const detectedPattern = patterns.find(({ pattern }) => pattern.test(code));
  return detectedPattern;
}

run().catch(console.dir);
