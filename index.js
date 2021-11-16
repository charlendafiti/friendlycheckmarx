const fs = require('fs');
const { exit } = require('process');
const { relativePathToAliceOnWorkspace } = require('./config.js')
let fileToSpec = './warnings.log'
let file;

try {
    file = fs.readFileSync(fileToSpec, 'utf-8');
} catch (error) {
    console.log('Não foi possível encontrar o arquivo: '+fileToSpec);
    process.exit();
}


let slices = file.split('WARNING');
let errors = []

//console.log( slices );
//exit();

let typesOfErrors = [];
let filesAffected = [];


fs.readFileSync('./warnings.log', 'utf-8');

slices.forEach(function (item) {
    if (item.search('checkmarx') > -1 && item.search('Vulnerability:') > -1) {
        cleanObject = [];


        try {
            
            //Separar vulnerabilidade de source e destination
            cleanObject.Vulnerability = item.split(': Destination')[0]
            cleanObject.Destination = item.split(': Destination')[1].split(' Source')[0]
            cleanObject.Source = item.split(': Destination')[1].split(', Source')[1]
            cleanObject.Object = cleanObject.Destination.split('object=')[1]
            cleanObject.Destination = cleanObject.Destination.split('object=')[0]

        } catch ( error ){
            console.log('Erro na estrutura da string: ', item);
        }

        
        item = cleanObject;
        let finalObject = [];
        
        finalObject['typeOfError'] = cleanObject.Vulnerability.replace('\[', '').trim().split(' ')[2]
        
        //Filter weight of error
        let weight = cleanObject.Vulnerability.replace('\[', '').trim().split(' ')[3]
        let replaceWeight = new RegExp("\\(|\\)",'g')
        weight = weight.replace(replaceWeight,'').split('|')[0]

        finalObject.weight = weight
        

        try {
            if (!!cleanObject.Source) {
                finalObject['details'] = cleanObject.Source.replace('\[', '').replace('\]', '').split(',')
            } else {
                finalObject['details'] = cleanObject.Destination.replace('\[', '').replace('\]', '').split(',')
            }
        } catch (error) {
            console.log('Erro na estrutura do objeto: ', finalObject);
        }


        finalObject.details.forEach(param => {
            param = param.replace('\[', '').replace('\]', '')
            param = param.split('=');
            finalObject[param[0].trim().replace(' ', '_')] = param[1]
        })

        finalObject.column = finalObject.column.split('\n')[0]


        //Resume of error types
        if (!typesOfErrors[finalObject['typeOfError']]) {
            typesOfErrors[finalObject['typeOfError']] = 1;
        } else {
            typesOfErrors[finalObject['typeOfError']]++
        }

        //Resume of fileNames
        if (!filesAffected[finalObject.filename]) {
            filesAffected[finalObject.filename] = [];
            filesAffected[finalObject.filename].totalErrors = 0;
        }

        
        if (!filesAffected[finalObject.filename][finalObject.typeOfError+'_'+weight]) {
            filesAffected[finalObject.filename][finalObject.typeOfError+'_'+weight] = []
        }

        //Push the error reference to links
        let includeFolder = !!finalObject.folder ? finalObject.folder+'\/' : '';
        if (!filesAffected[finalObject.filename][finalObject.typeOfError+'_'+weight].includes(relativePathToAliceOnWorkspace + includeFolder + finalObject.filename + ':' + finalObject.line + ':' + finalObject.column)) {
            filesAffected[finalObject.filename][finalObject.typeOfError+'_'+weight].push(relativePathToAliceOnWorkspace + includeFolder + finalObject.filename + ':' + finalObject.line + ':' + finalObject.column)
        }

        filesAffected[finalObject.filename].totalErrors++
        delete finalObject.details;
        errors.push(finalObject);
    }
})

console.log(filesAffected);
console.log(typesOfErrors)
