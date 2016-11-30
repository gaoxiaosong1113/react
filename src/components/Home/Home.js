import React, {Component} from 'react';
import Banner from '../Banner/Banner';
import Header from '../Header/Header';

class Home extends Component {
    state = {
        title: "gxspp.com"
    };
    render() {
        return (
            <div>
                < Header title={this.state.title}/>
                < Banner/>
            </div>
        );
    }
}

export default Home;