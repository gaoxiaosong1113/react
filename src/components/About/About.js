import React, {Component} from 'react';

require('./About.css')

class About extends Component {
    state = {
        BodyWidth: document.body.clientWidth,
        BodyHeight: document.documentElement.clientHeight,
        item: 0,
        time: 200,
        length: 6,
        transition: "all 0.4s ease-out",
        transform: "translate3d(0px, 0px, 0px)",
        ItmeLi: [0, 1, 2, 3, 4, 5],
        BannerSet: '',
        startPos: '',
        isScrolling: false,
        BoxModel: 0
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
        };

    }

    TouchMove(event) {
        if (!this.state.isScrolling) {
            return;
        }
        var moveTouch = event.changedTouches[0];
        var movePos = {
            x: moveTouch.pageX - this.state.startPos.x,
            y: moveTouch.pageY - this.state.startPos.y
        };

        this.state.isScrolling = Math.abs(movePos.x) < Math.abs(movePos.y);

        if (this.state.isScrolling) {
            var moveOffset = movePos.y - this.state.item * this.state.BodyHeight;
            this.setState({transition: "all 0s ease-out"});
            this.setState({transform: 'translate3d(0px, ' + moveOffset + 'px, 0px)'})
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
            if (Math.abs(endPos.y) > 50) {
                if (endPos.y > 0) {
                    if (this.state.item == 0) {
                        this.setState({isScrolling: false});
                        this.setState({item: 0}, function () {
                            this.Next();
                        })
                    } else {
                        this.PrevPage();
                    }

                } else if (endPos.y < 0) {
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
        this.setState({transform: 'translate3d(0px, ' + -(this.state.item * (this.state.BodyHeight - this.state.BoxModel)) + 'px, 0px)'});
    }

    render() {
        var JlStyles = {
            width: this.state.BodyWidth,
            height: this.state.length * parseFloat(this.state.BodyHeight),
            transition: this.state.transition,
            transform: this.state.transform
        };
        var JyStyles = {
            width: this.state.BodyWidth,
            height: this.state.BodyHeight
        };
        var SMain = {
            width: this.state.BodyWidth,
            height: this.state.BodyHeight
        }
        var SMainLi = {
            width: this.state.BodyWidth
        }
        return (

            <div className="jl-slide" style={ JyStyles }>
                <div className="slide-box" style={ JlStyles } onTouchStart={this.TouchStart.bind(this)} onTouchMove={this.TouchMove.bind(this)} onTouchEnd={this.TouchEnd.bind(this)}>
                    <div className="sMain" style={ SMain }>
                        <div className="sMain-1">
                            <div className="gxs-tx">
                                <img src={require('../../static/images/gxs_tx.png')} alt=""/>
                            </div>
                            <div className="gxs-title">
                                <img src={require('../../static/images/gxs_title.png')} alt=""/>
                            </div>
                            <div className="gxs-text">
                                <p><span>高晓松</span></p>
                                <p>Web前端工程师 / UI设计师</p>
                            </div>
                        </div>
                    </div>
                    <div className="sMain" style={ SMain }>
                        <div className="sMain-2">
                            <div className="sMain-title">个人资料</div>
                            <div className="sMain-text-warp">
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>毕业院校</div>
                                    <div className="sMain-text-body">
                                        <p>北京财经专修学院</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>专业</div>
                                    <div className="sMain-text-body">
                                        <p>视觉设计</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>籍贯</div>
                                    <div className="sMain-text-body">
                                        <p>山西省临汾市</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>电话</div>
                                    <div className="sMain-text-body">
                                        <p>15601064107</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>邮箱</div>
                                    <div className="sMain-text-body">
                                        <p>704041637@qq.com</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>出生日期</div>
                                    <div className="sMain-text-body">
                                        <p>1994年</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="sMain" style={ SMain }>
                        <div className="sMain-2">
                            <div className="sMain-title">开发工具</div>
                            <div className="sMain-text-warp">
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>我的IDE</div>
                                    <div className="sMain-text-body">
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/ws.png')}/>
                                            </div>
                                            <p>WebStorm</p>
                                        </div>
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/s.png')}/>
                                            </div>
                                            <p>Sublime</p>
                                        </div>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>我的技能</div>
                                    <div className="sMain-text-body">
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/H5.png')}/>
                                            </div>
                                            <p>HTML5</p>
                                        </div>
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/css.png')}/>
                                            </div>
                                            <p>css3</p>
                                        </div>
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/js.png')}/>
                                            </div>
                                            <p>Javascript</p>
                                        </div>
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/b.png')}/>
                                            </div>
                                            <p>Bootstrap</p>
                                        </div>
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/jq.png')}/>
                                            </div>
                                            <p>jQuery</p>
                                        </div>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>我的辅助工具</div>
                                    <div className="sMain-text-body">
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/ps.png')}/>
                                            </div>
                                            <p>Photoshop</p>
                                        </div>
                                        <div className="icon-kfgj">
                                            <div className="icon-kfgj-img">
                                                <img src={require('../../static/images/ai.png')}/>
                                            </div>
                                            <p>Illustrator</p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="sMain" style={ SMain }>
                        <div className="sMain-2">
                            <div className="sMain-title">职业技能</div>
                            <div className="sMain-text-warp">
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>前端技能</div>
                                    <div className="sMain-text-body">
                                        <p>1、精通JavaScript、Ajax、DOM等前端技术，深入了解JavaScript及其面向对象的编程思想；</p>
                                        <p>2、 熟练掌握DIV+CSS页面架构和布局方式，精通HML5、CSS3等相关技术；</p>
                                        <p>3、熟悉W3C标准、Web语义化等有深刻理解；</p>
                                        <p>4、对JQuery,Bootstrap等流行框架使用熟练；</p>
                                        <p>5、对用户体验、交互操作流程、及用户需求有深入理解；</p>
                                        <p>6、熟练使用WebStrom、sublime等工作相关软件</p>
                                        <p>7、熟悉掌握ES6新特性</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>UI技能</div>
                                    <div className="sMain-text-body">
                                        <p>1、掌握基本配色；</p>
                                        <p>2、图形设计、用户体验设计、banner设计、网站设计、app界面设计；</p>
                                        <p>3、熟练使用Photostop，Illustrator等工作相关软件；</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="sMain" style={ SMain }>
                        <div className="sMain-2">
                            <div className="sMain-title">工作经历</div>
                            <br/>
                            <br/>
                            <div className="sMain-text-warp">
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>六行君通信息科技股份有限公司 | <span>web前端开发</span></div>
                                    <div className="sMain-text-body">
                                        <p>岗位职责：</p>
                                        <p>把设计出来的效果图，用html+css制作成符合w3c标准的页面，并配合后台进行相关页面的修改。</p>
                                        <p>2013/04 —— 2015/02</p>
                                    </div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>六行普惠投资管理有限公司 | <span>web前端开发</span></div>
                                    <div className="sMain-text-body">
                                        <p><span>涉及项目：</span></p>
                                        <p>1：根据UI效果图切图，并写成html页面；</p>
                                        <p>2：开发工作需要插件；</p>
                                        <p>3：使用vue.js实现网站模块化；</p>
                                        <p>4：使用git做版本控制</p>
                                        <br/>
                                        <p><span>工作技能</span></p>
                                        <p>基本SHELL命令使用</p>
                                        <p>使用git做项目管理</p>
                                        <p>使用webpack搭建开发环境</p>
                                        <p>熟悉npm包管理器</p>
                                        <p>使用babel做代码编译</p>
                                        <p>2015/02 —— 至今</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div className="sMain" style={ SMain }>
                        <div className="sMain-2">
                            <div className="sMain-title">联系我</div>
                            <div className="sMain-text-warp">
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>手机 | <span>15601064107</span></div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>邮箱 | <span>704041637@qq.com</span></div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>个人网站 | <a href="http://www.gxspp.com"><span>http://www.gxspp.com</span></a></div>
                                </div>
                                <div className="sMain-text">
                                    <div className="sMain-text-head"><i className="gxs_icon"></i>不忘初心，方能始终</div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <ul className="slide-item">
                    <li className={this.state.item == this.state.ItmeLi[0] ?  "cur" :""}>1</li>
                    <li className={this.state.item == this.state.ItmeLi[1] ?  "cur" :""}>2</li>
                    <li className={this.state.item == this.state.ItmeLi[2] ?  "cur" :""}>3</li>
                    <li className={this.state.item == this.state.ItmeLi[3] ?  "cur" :""}>4</li>
                    <li className={this.state.item == this.state.ItmeLi[4] ?  "cur" :""}>5</li>
                    <li className={this.state.item == this.state.ItmeLi[5] ?  "cur" :""}>6</li>
                </ul>
            </div>
        )
    }
}

export default About



