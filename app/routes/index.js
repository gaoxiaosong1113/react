import React, { Component } from 'react';
import { Route, IndexRoute } from 'react-router';
import { App, Home, About, Ceshi } from '../components';

export default (
  <Route path="/" component={App}>
    <IndexRoute component={Home} />
    <Route path="home" component={Home} />
    <Route path="about" component={About} />
    <Route path="ceshi" component={Ceshi} />
  </Route>
)