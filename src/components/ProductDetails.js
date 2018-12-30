import React from 'react';
import { connect } from 'react-redux';
import { fetchProduct } from '../actions/products';
import { history } from '../routers/AppRouter';
import paths from '../helpers/paths';
import DeleteModal from '../components/DeleteModal';
import { setDeleteModal } from '../actions/products';

class ProductDetails extends React.Component {
    componentDidMount () {
        this.props.dispatch(fetchProduct(this.props.id));
    }
    handleCancel = () =>{
        this.props.dispatch(setDeleteModal('STATE_INVISIBLE'));
    }
    render() {
        const { product } = this.props.products;
        const { level } = this.props.auth.userDetails;
        const { deleteModal } = this.props.products;
        if(product[0]){
        return (
                <div className="product-details" id="product">
                    <img src={require("../images/item1.jpg")} />
                    <div className="quant-avail">{product[0].product_quantity} available</div>
                    <div className="min-invent">Minimum Inventory: {product[0].minimum_inventory}</div>
                    <div className="name-description detailed-description">{product[0].product_name}</div>
                    
                    <div className="price detailed-price">
                        $<span className="actual-price">{ product[0].product_price }</span> per item
                                </div>
                    
                                { level === 2 && <input type="button" className="confirm modify" id="modify" value="Modify" onClick = {()=>{
                            history.push(paths.modifyProduct);
                    }}></input>}
                    
                    { level === 2 && <input type="button" className="delete" value="Delete" onClick = { ()=>{
                        this.props.dispatch(setDeleteModal('STATE_VISIBLE'));
                    }}></input>}
                    
                    { level === 1 && <input type="button" className="confirm modify"  value="Add to Cart"></input>}
                    
                    {deleteModal === 'STATE_VISIBLE' &&  <DeleteModal handleCancel = {this.handleCancel}/>}
                </div>
                
            
            

        );
        } else {
            return <div></div>
        }
    }
}

const mapStateToProps = (state) => state;

export default connect( mapStateToProps)(ProductDetails); 
