import React, {Component} from 'react';
import $ from 'jQuery';
import {Router, Route, hashHistory, Link} from 'react-router';

class Banner extends Component {
    state = {
        BodyWidth: document.body.clientWidth,
        item: 0,
        time: 200,
        length: 4,
        transition: "all 0.4s ease-out",
        transform: "translate3d(0px, 0px, 0px)",
        ItmeLi: [0, 1, 2, 3],
        BannerSet: '',
        startPos: '',
        isScrolling: false,
        BoxModel: 30
    };

    TtemClick(index) {
        clearInterval(this.state.BannerSet);
        this.setState({item: index}, function () {
            this.Next();
        });
        this.componentDidMount()
    }

    TouchStart(event) {
        this.setState({isScrolling: true});
        var startTouch = event.changedTouches[0];
        this.state.startPos = {
            x: startTouch.pageX,
            y: startTouch.pageY,
            time: +new Date()
        }
    }

    TouchMove(event) {
        if (!this.state.isScrolling) {
            return;
        }
        event.preventDefault();
        var moveTouch = event.changedTouches[0];
        var movePos = {
            x: moveTouch.pageX - this.state.startPos.x,
            y: moveTouch.pageY - this.state.startPos.y
        };

        this.state.isScrolling = Math.abs(movePos.x) > Math.abs(movePos.y);
        if (this.state.isScrolling) {
            var moveOffset = movePos.x - this.state.item * this.state.BodyWidth;
            this.setState({transform: 'translate3d(' + moveOffset + 'px, 0px, 0px)'});
            this.setState({transition: "all 0s ease-out"});
        }
    }

    TouchEnd(event) {
        clearInterval(this.state.BannerSet);
        if (!this.state.isScrolling) {
            return;
        }
        var duration = +new Date() - this.state.startPos.time;
        var endTouch = event.changedTouches[0];
        var endPos = {
            x: endTouch.pageX - this.state.startPos.x,
            y: endTouch.pageY - this.state.startPos.y
        };

        if (duration > 10) {
            if (Math.abs(endPos.x) > 50) {
                if (endPos.x > 0) {
                    if (this.state.item == 0) {
                        this.setState({isScrolling: false});
                        this.setState({item: 0}, function () {
                            this.Next();
                        })
                    } else {
                        this.PrevPage();
                    }
                } else if (endPos.x < 0) {
                    if (this.state.item == this.state.length - 1) {
                        this.setState({isScrolling: false});
                        this.setState({item: this.state.length - 1}, function () {
                            this.Next();
                        })
                    } else {
                        this.NextPage();
                    }

                } else {
                    this.setState({isScrolling: false})
                }
            }
        }
        this.componentDidMount()
    }

    componentDidMount() {

        this.state.BannerSet = setInterval(() => {
            if (this.state.item < this.state.length - 1) {
                this.setState({transition: "all 0.4s ease-out"});
                this.NextPage()
            } else {
                this.setState({item: 0}, function () {
                    this.Next()
                });
            }
        }, 3000)
    }

    componentWillUnmount() {
        clearInterval(this.state.BannerSet)
    }

    PrevPage() {
        this.setState({item: this.state.item - 1}, function () {
            this.Next()
        });
    }

    NextPage() {
        this.setState({item: this.state.item + 1}, function () {
            this.Next()
        });
    }

    Next() {
        this.setState({transition: "all 0.4s ease-out"});
        this.setState({transform: 'translate3d(' + -(this.state.item * (this.state.BodyWidth - this.state.BoxModel)) + 'px, 0px, 0px)'});
    }

    render() {
        var BannerStyles = {
            width: this.state.length * parseFloat(this.state.BodyWidth),
            transition: this.state.transition,
            transform: this.state.transform
        };
        var SMain = {
            width: this.state.BodyWidth - 30
        };
        var SMainLi = {
            width: this.state.BodyWidth
        };

        return (

            <div className="container-fluid">
                <div className="content-box banner">
                    <div className="slide">
                        <div className="slide-box" style={BannerStyles} onTouchStart={this.TouchStart.bind(this)} onTouchMove={this.TouchMove.bind(this)} onTouchEnd={this.TouchEnd.bind(this)}>
                            <div className="sMain" style={SMain}><img src={require('../../static/images/banner1.png')} alt=""/></div>
                            <div className="sMain" style={SMain}><img src={require('../../static/images/banner1.png')} alt=""/></div>
                            <div className="sMain" style={SMain}><img src={require('../../static/images/banner1.png')} alt=""/></div>
                            <div className="sMain" style={SMain}><img src={require('../../static/images/banner1.png')} alt=""/></div>
                        </div>
                        <ul className="slide-item">
                            <li className={this.state.item == this.state.ItmeLi[0] ?  "cur" :""} onClick={this.TtemClick.bind(this,this.state.ItmeLi[0])}></li>
                            <li className={this.state.item == this.state.ItmeLi[1] ?  "cur" :""} onClick={this.TtemClick.bind(this,this.state.ItmeLi[1])}></li>
                            <li className={this.state.item == this.state.ItmeLi[2] ?  "cur" :""} onClick={this.TtemClick.bind(this,this.state.ItmeLi[2])}></li>
                            <li className={this.state.item == this.state.ItmeLi[3] ?  "cur" :""} onClick={this.TtemClick.bind(this,this.state.ItmeLi[3])}></li>
                        </ul>
                    </div>
                </div>
                <div className="content-box img-auto slide-img"></div>
                <div className="content-box me-text">
                    <Link to="/about">
                        <div className="fl col-xs-6 box-resume">
                            <p>我的简历</p>
                        </div>
                    </Link>
                    <Link to="/project">
                        <div className="fl col-xs-6 box-case">
                            <p>我的Project</p>
                        </div>
                    </Link>
                </div>
            </div>
        );
    }
}

export default Banner;