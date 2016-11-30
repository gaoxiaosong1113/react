var path = require('path');
var webpack = require('webpack');
var ExtractTextPlugin = require("extract-text-webpack-plugin");
var publicPath = path.resolve(__dirname, 'public');
var HtmlWebpackPlugin = require('html-webpack-plugin');
var openBrowserWebpackPlugin = require('open-browser-webpack-plugin');

module.exports = {
    entry: {
        index: [
            'webpack/hot/dev-server',
            'webpack-dev-server/client?http://localhost:8080',
            path.resolve(__dirname, 'src/index.js')
        ],
        vendor: ['react', 'react-dom']
    },
    output: {
        path: publicPath,
        filename: '[name].js?[hash]'
    },
    resolve: {
        extension: ['', '.js', '.jsx', '.json']
    },
    module: {
        loaders: [
            {
                test: /\.js$/,
                loaders: ['react-hot', 'babel'],
                exclude: path.resolve(__dirname, 'node_modules')
            },
            {
                test: /\.css/,
                loader: ExtractTextPlugin.extract("style-loader", "css-loader")
            },
            {
                test: /\.less/,
                loader: ExtractTextPlugin.extract("style-loader", "css-loader!less-loader")
            },
            {
                test: /\.(png|jpg)$/,
                loader: 'url?limit=20000&name=images/[name].[ext]'
            },
            {
                test: /\.(woff|woff2|ttf|svg|eot)(\?v=\d+\.\d+\.\d+)?$/,
                loader: "url?limit=10000&name=svg/[name].[ext]"
            }
        ]
    },
    plugins: [
        new webpack.HotModuleReplacementPlugin(),
        new webpack.NoErrorsPlugin(),
        new webpack.optimize.CommonsChunkPlugin('vendor', 'vendor.js?[hash]'),
        new ExtractTextPlugin("[name].css?[hash]", {
            allChunks: true,
            disable: false
        }),
        new HtmlWebpackPlugin({
            title: 'zhufeng-react',
            template: './index.html'
        }),
        new openBrowserWebpackPlugin({
            url: 'http://localhost:8080'
        })
    ],
    devtool: 'cheap-module-source-map'
};