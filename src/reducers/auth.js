
const defaultState = {
    loginState: 'STATE_NOT_LOGGED',
    loginError: undefined,
    userDetails: {}
};


 export default (state = defaultState, action) => {
    switch (action.type) {
        case 'SET_USER':
        const userDetails = action.userDetails;
            return {
                ...state,
            userDetails
        }
        case 'SET_LOGIN_STATE':
           const { loginState } = action;
           return {
               ...state,
               loginState
           }  
        case 'SET_LOGIN_ERROR':
           const { loginError } = action;
           return {
               ...state,
               loginError
           }       
        default : 
            return state
    }
};





