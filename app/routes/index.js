import React, {Component} from 'react';
import {Route, IndexRoute} from 'react-router';
import {App, Home, About, MyText, Project, Article} from '../components';

export default (
    <Route path="/" component={App}>
        <IndexRoute component={Home}/>
        <Route path="home" component={Home}/>
        <Route path="about" component={About}/>
        <Route path="mytext" component={MyText}/>
        <Route path="project" component={Project}/>
        <Route path="article" component={Article}/>
    </Route>
)