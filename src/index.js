'use strict';

import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import { Router, hashHistory  } from 'react-router';
import routes from './routes/index.js';

require('bootstrap/dist/css/bootstrap.css');
require('./static/style/animate.css');
require('./static/style/sherd.css');
require('./static/style/style.css');

let root = document.getElementById('app');
ReactDOM.render(<Router routes={routes} history={hashHistory} />, root);