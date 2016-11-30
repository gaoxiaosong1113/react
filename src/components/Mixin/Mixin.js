import React, {Component} from 'react';
import Button from '../Button/Button';
import Taby from '../Tab/Tab';

let Mixin = MixinComponent => class extends Component {
    render() {
        return (
            <MixinComponent update={this.update}{...this.state}{...this.props} />
        )
    }
}

let ButtonMixed = Mixin(Button);
let TabMixed = Mixin(Taby);


class Mixins extends Component {
    render() {
        return (
            <div>
                <ButtonMixed txt="button"/>
                <Taby />
            </div>
        )
    }
}

export default Mixins;