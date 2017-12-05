/**
 * Connect to MongoDB.
 */
var mongoose = require('mongoose');
var mongoDB = process.env.MONGODB || 'mongodb://127.0.0.1/austin-dase';
mongoose.Promise = global.Promise;
//mongoose.connect(process.env.MONGODB_URI || process.env.MONGOLAB_URI);
mongoose.connect(mongoDB || process.env.MONGODB_URI, {
    useMongoClient: true
});


var db_conn = mongoose.connection.on('error', function(err) {
    console.error(err);
    console.log('%s MongoDB connection error. Please make sure MongoDB is running.', chalk.red('✗'));
    process.exit();
});

module.exports = db_conn;