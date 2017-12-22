var path = require('path')

module.exports = {
  entry: [
    './src/index.js'
  ],
  output: {
    path: path.join(__dirname, '/dist/'),
    filename: 'jwt.min.js',
    library: 'JWT',
    libraryTarget: 'var'
  },
  module: {
    loaders: [
      {
        test: /\.js$/,
        loader: 'babel-loader'
      }
    ]
  },
  externals: {
    'text-encoding': 'TextEncoder',
    '@trust/webcrypto': 'crypto',
    'fs': {},
    'node-fetch': 'fetch'
  },
  devtool: 'source-map'
}
