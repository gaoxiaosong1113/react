import React, {Component} from 'react';
import ReactDOM from 'react-dom';
import {Router, IndexRoute, Link} from 'react-router';

require('./Header.css');

class Header extends Component {
    state = {
        meng: true
    };

    HeaderMeng() {
        this.setState({meng: !this.state.meng})
    }

    componentWillReceiveProps() {
        this.setState({meng: true})
    }

    componentDidMount() {
        this.setState({meng: true})
    }

    componentWillUnmount() {
        this.HeaderMeng()
    }

    render() {
        var MengStyle = {
            display: this.state.meng ? 'none' : 'block'
        };
        return (
            <div>
                <div className="gx-nav container-fluid nav">
                    <div className="menu">
                        <button type="button" className="gx-btn btn" onClick={ this.HeaderMeng.bind(this) }>
                            <span className="nav-bar"></span>
                            <span className="nav-bar"></span>
                            <span className="nav-bar"></span>
                        </button>
                    </div>
                    <div className="logo">
                        <Link to="/home"></Link>
                    </div>
                    <div className="home-btn">
                        <button type="button" className="gx-btn btn">
                            {this.props.title}
                        </button>
                    </div>
                </div>
                <div className="nav-bg"></div>

                <div className={this.state.meng ? 'box-fluid nav-list' :  'box-fluid nav-list an' }>
                    <Link to="/home">
                        <div className="box-wid-12 nav-list-l">首页</div>
                    </Link>
                    <Link to="/about">
                        <div className="box-wid-12 nav-list-l">我的简历</div>
                    </Link>
                    <Link to="/project">
                        <div className="box-wid-12 nav-list-l">我的Project</div>
                    </Link>
                    <Link to="/mytext">
                        <div className="box-wid-12 nav-list-l">我的笔记</div>
                    </Link>
                    <Link to="">
                        <div className="box-wid-12 nav-list-l">插件开发</div>
                    </Link>
                </div>
            </div>
        )
    }
}

export default Header;
