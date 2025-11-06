// craco.config.js
const path = require("path");
require("dotenv").config();

const webpackConfig = {
  webpack: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
    configure: (webpackConfig) => {
      // Add ignored patterns to reduce watched directories
      webpackConfig.watchOptions = {
        ...webpackConfig.watchOptions,
        ignored: [
          '**/node_modules/**',
          '**/.git/**',
          '**/build/**',
          '**/dist/**',
          '**/coverage/**',
          '**/public/**',
        ],
      };

      // Ignore source map warnings for @mediapipe/tasks-vision
      webpackConfig.module.rules.push({
        test: /\.m?js$/,
        enforce: 'pre',
        use: ['source-map-loader'],
        resolve: {
          fullySpecified: false,
        },
      });
      webpackConfig.ignoreWarnings = [/Failed to parse source map/];

      return webpackConfig;
    },
  },
};

module.exports = webpackConfig;
