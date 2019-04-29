
const defaultState = {
    cartAddModalState: ''
};


 export default (state = defaultState, action) => {
    switch (action.type) {
        case 'SET_ADD_CART_MODAL':
            return {
                ...state,
            cartAddModalState: action.cartAddModalState
        }
        default : 
            return state
    }
};





