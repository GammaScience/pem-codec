// Karma configuration
// Generated on Sat Mar 30 2019 15:35:20 GMT+0000 (GMT)

module.exports = function(config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',


    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['jasmine', 'karma-typescript' ],

    plugins: [
     require('karma-jasmine'),
     require('karma-coverage'),
     require('karma-typescript'),
     require('karma-jasmine-html-reporter'),
     require('karma-chrome-launcher'),

    ],
    client: {
        clearContext: false    // will show the results in browser once all the testcases are loaded
    },
    // list of files / patterns to load in the browser
    files: [
      'src/*.ts'
    ],


    // list of files / patterns to exclude
    exclude: [
      '**/.*.swp'
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
            "**/*.ts": "karma-typescript" // *.tsx for React Jsx
    },


    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    //reporters: ['progress'],
    reporters: ['kjhtml', 'progress', 'coverage' ],

    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['Chrome'],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity
  })
}
