import { h, Component } from 'preact';
import './ButtonIcon.scss';

interface PropTypes {
  className?: string;
  frameless?: boolean;
  src: string;
  alt: string;
  [prop: string]: any;
}

interface StateTypes {

}

export default class ButtonIcon extends Component<PropTypes, StateTypes> {
  constructor(props: PropTypes) {
    super(props)
  }

  render() {
    const {
      className,
      ref,
      src,
      alt,
      frameless,
      ...remainingProps,
    } = this.props
    const framelessClass = frameless ? 'ButtonIcon-frameless' : ''
    return (
      <button className={`ButtonIcon ${framelessClass} ${className}`}
        {...remainingProps}
      >
        <img className="ButtonIcon-img"
          src={src}
          alt={alt}
        />
      </button>
    );
  }
}

ButtonIcon.defaultProps = {
  className: '',
  frameless: false,
}
