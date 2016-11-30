import React, {Component} from 'react';
import {Router, IndexRoute, Link} from 'react-router';
import Header from '../Header/Header';

require('./Project.css');

class Project extends Component {
    state = {
        title: "我的Project"
    };
    render() {
        return (
            <div className="myText">
                < Header title={this.state.title}/>
                <div className="container-fluid alert-init">
                    <div className="alert alert-info" role="alert">欢迎</div>
                </div>
                <div className="container-fluid">
                    <div className="list-group">
                        <Link to="/article" className="list-group-item">文章1</Link>
                        <Link to="/article" className="list-group-item">文章2</Link>
                        <Link to="/article" className="list-group-item">文章3</Link>
                        <Link to="/article" className="list-group-item">文章4</Link>
                        <Link to="/article" className="list-group-item">文章5</Link>
                    </div>
                </div>
                <nav className="text-center">
                    <ul className="pagination">
                        <li><Link to="/article">1</Link></li>
                        <li><Link to="/article">2</Link></li>
                        <li><Link to="/article">3</Link></li>
                        <li><Link to="/article">4</Link></li>
                        <li><Link to="/article">5</Link></li>
                    </ul>
                </nav>
            </div>
        )
    }
}

export default Project;
