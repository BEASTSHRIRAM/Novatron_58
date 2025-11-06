// craco.config.js
const path = require("path");
require("dotenv").config();

const webpackConfig = {
  webpack: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
    configure: (webpackConfig) => {
      // Ignore Mediapipe source-map warnings
      webpackConfig.ignoreWarnings = [
        {
          module: /@mediapipe\/tasks-vision/,
        },
      ];

      // Reduce directories watched for faster rebuild
      webpackConfig.watchOptions = {
        ...webpackConfig.watchOptions,
        ignored: [
          '/node_modules/',
          '/.git/',
          '/build/',
          '/dist/',
          '/coverage/',
          '/public/',
        ],
      };

      return webpackConfig;
    },
  },
};

module.exports = webpackConfig;