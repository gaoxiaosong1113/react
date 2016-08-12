import React, {Component} from 'react';
import {Router, IndexRoute, Link} from 'react-router';
import Header from '../Header/Header';

require('./Article.css');

class Article extends Component {
    state = {
        title: "我的Article"
    };

    render() {
        return (
            <div className="myText">
                < Header title={this.state.title}/>
                <div className="container-fluid article-content">
                    <div className="page-header">
                        <h1>Hello, world!
                            <small>Subtext for header</small>
                        </h1>
                    </div>

                    <div className="page-body">
                        <div className="jumbotron">
                            <h1>Hello, world!</h1>
                            <p>我的是九十年代</p>
                            <p><a className="btn btn-primary btn-lg" href="#" role="button">Learn more</a></p>
                        </div>
                        <div className="page-font">
                            <p>在 JavaScript 代码里写着 XML 格式的代码称为 JSX；可以去 JSX 语法 里学习更多 JSX 相关的知识。为了把 JSX 转成标准的 JavaScript，我们用，然后通过Babel转换成在浏览器中真正执行的内容。</p>
                        </div>
                    </div>
                </div>
            </div>
        )
    }
}

export default Article;
