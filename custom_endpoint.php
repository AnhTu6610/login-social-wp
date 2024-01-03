
// -------------------------------------------------------------------------> custom endpoint
use Tmeister\Firebase\JWT\JWT;
use Tmeister\Firebase\JWT\Key;
add_action('rest_api_init', 'register_social_login_endpoint');
function register_social_login_endpoint() {
    register_rest_route('jwt-auth/v1', '/social-login', array(
        'methods'  => 'POST',
        'callback' => 'process_social_login',
    ));
}

// Process social login
function process_social_login(WP_REST_Request $request) {
    $providerID = $request->get_param('provider');
    $body = $request->get_body();
    $authOptions['access_token_data'] = $body;
    try {
        $user_id = nslLinkOrRegister($providerID, $authOptions);
        if ($user_id == false){
            return new WP_Error('error', "Invalid information");
        }
        $user = get_user_by('ID', $user_id);
        return generate_token($user);
    } catch (Exception $e) {
        //handle the exceptions
        return new WP_Error('error', $e->getMessage());
    }
}
function nslLinkOrRegister($providerID, $authOptions) {
    $provider = NextendSocialLogin::getProviderByProviderID($providerID);
    if ($provider) {
        $social_user_id = $provider->getAuthUserDataByAuthOptions('id', $authOptions);
        if ($social_user_id) {
            /**
             * Step2: Check if the social media account is linked to any WordPress account.
             */
            $wordpress_user_id = $provider->getUserIDByProviderIdentifier($social_user_id);

            if (!is_user_logged_in()) {

                /**
                 * Step3: Handle the logged out users
                 */
                if ($wordpress_user_id !== null) {
                    $provider->triggerSync($wordpress_user_id, $authOptions, "login", true);

                    /**
                     * Step 4: This social media account is already linked to a WordPress account.-> Log the user in using the returned User ID.
                     */

                    return $wordpress_user_id;
                } else {
                    /**
                     * Step 5: This social media account is not linked to any WordPress account, yet. -> Find out if we need to Link or Register
                     */

                    $wordpress_user_id = false;

                    /**
                     * Step 6: Attempt to match a WordPress account with the email address returned by the provider:
                     */
                    $email = $provider->getAuthUserDataByAuthOptions('email', $authOptions);
                    if (empty($email)) {
                        $email = '';
                    } else {
                        $wordpress_user_id = email_exists($email);
                    }

                    if ($wordpress_user_id !== false) {
                        /**
                         * Step 7: There is an email address match -> Link the existing user to the provider
                         */
                        if ($provider->linkUserToProviderIdentifier($wordpress_user_id, $social_user_id)) {
                            $provider->triggerSync($wordpress_user_id, $authOptions, "login", true);

                            //log the user in if the linking was successful

                            return $wordpress_user_id;
                        } else {
                            // Throw error: User already have another social account from this provider linked to the WordPress account that has the email match. They should use that account.
                        }

                    } else {
                        /**
                         * Step 8: There is no email address match -> Register a new WordPress account, e.g. with wp_insert_user()
                         * fill $user_data with the data that the provider returned
                         */
                        $user_data = array(
                            'user_login'   => $provider->getAuthUserDataByAuthOptions('name', $authOptions),
                            'user_email'   => $email,
                            //use the email address returned by the provider, note: it can be empty in certain cases
                            'user_pass'    => wp_generate_password(),
                            'display_name' => $provider->getAuthUserDataByAuthOptions('name', $authOptions),
                            'first_name'   => $provider->getAuthUserDataByAuthOptions('first_name', $authOptions),
                            'last_name'    => $provider->getAuthUserDataByAuthOptions('last_name', $authOptions),
                        );


                        $wordpress_user_id = wp_insert_user($user_data);

                        if (!is_wp_error($wordpress_user_id) && $wordpress_user_id) {
                            /**
                             * Step 9: Link the new user to the provider
                             */
                            if ($provider->linkUserToProviderIdentifier($wordpress_user_id, $social_user_id, true)) {
                                $provider->triggerSync($wordpress_user_id, $authOptions, 'register', false);
                                $provider->triggerSync($wordpress_user_id, $authOptions, "login", true);

                                //The registration and the linking was successful -> log the user in.

                                return $wordpress_user_id;
                            }
                        } else {
                            //Throw error: There was an error with the registration
                        }
                    }
                }
            } else {
                /**
                 * Step 10: Handle the linking for logged in users
                 */
                $current_user = wp_get_current_user();
                if ($wordpress_user_id === null) {
                    // Let's connect the account to the current user!
                    if ($provider->linkUserToProviderIdentifier($current_user->ID, $social_user_id)) {
                        //account is linked, we don't need to trigger additional actions we just need to sync the avatar
                        $provider->triggerSync($current_user->ID, $authOptions, false, true);

                        return $current_user->ID;
                    } else {
                        //Throw error: Another social media account is already linked to the current WordPress account. The user need to unlink the currently linked one and he/she can link the this social media account.
                    }
                } else if ($current_user->ID != $wordpress_user_id) {
                    //Throw error: This social account is already linked to another WordPress user.
                }
            }
        }
    }

    return false;
}


 function generate_token( $user ) {
        $secret_key = defined( 'JWT_AUTH_SECRET_KEY' ) ? JWT_AUTH_SECRET_KEY : false;

        /** First thing, check the secret key if not exist return an error*/
        if ( ! $secret_key ) {
            return new WP_Error(
                'jwt_auth_bad_config',
                __( 'JWT is not configured properly, please contact the admin', 'wp-api-jwt-auth' ),
                [
                    'status' => 403,
                ]
            );
        }
        /** If the authentication fails return an error*/
        if ( is_wp_error( $user ) ) {
            $error_code = $user->get_error_code();

            return new WP_Error(
                '[jwt_auth] ' . $error_code,
                $user->get_error_message( $error_code ),
                [
                    'status' => 403,
                ]
            );
        }

        /** Valid credentials, the user exists create the according Token */
        $issuedAt  = time();
        $notBefore = apply_filters( 'jwt_auth_not_before', $issuedAt, $issuedAt );
        $expire    = apply_filters( 'jwt_auth_expire', $issuedAt + ( DAY_IN_SECONDS * 7 ), $issuedAt );

        $token = [
            'iss'  => get_bloginfo( 'url' ),
            'iat'  => $issuedAt,
            'nbf'  => $notBefore,
            'exp'  => $expire,
            'data' => [
                'user' => [
                    'id' => $user->data->ID,
                ],
            ],
        ];

        /** Let the user modify the token data before the sign. */
        $algorithm = get_algorithm();
        if ( $algorithm === false ) {
            return new WP_Error(
                'jwt_auth_unsupported_algorithm',
                __( 'Algorithm not supported, see https://www.rfc-editor.org/rfc/rfc7518#section-3',
                    'wp-api-jwt-auth' ),
                [
                    'status' => 403,
                ]
            );
        }
        
        $token = JWT::encode(
            apply_filters( 'jwt_auth_token_before_sign', $token, $user ),
            $secret_key,
            $algorithm
        );

        /** The token is signed, now create the object with no sensible user data to the client*/
     
        $data = [
            'token'             => $token,
            'user'                => $user,
//             'user_email'        => $user->data->user_email,
//             'user_nicename'     => $user->data->user_nicename,
//             'user_display_name' => $user->data->display_name,
        ];
//         unset($data['user']['data']['user_pass']);
        unset($data['user']->data->user_pass);
        /** Let the user modify the data before send it back */
        return apply_filters( 'jwt_auth_token_before_dispatch', $data, $user );
}

function get_algorithm() {
    $supported_algorithms = [
            'HS256',
            'HS384',
            'HS512',
            'RS256',
            'RS384',
            'RS512',
            'ES256',
            'ES384',
            'ES512',
            'PS256',
            'PS384',
            'PS512'
    ];
    $algorithm = apply_filters( 'jwt_auth_algorithm', 'HS256' );
    if ( ! in_array( $algorithm, $supported_algorithms ) ) {
        return false;
    }

    return $algorithm;
}
 
