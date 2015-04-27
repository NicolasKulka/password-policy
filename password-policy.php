<?php

/*
  Plugin Name: Password Policy
  Plugin URI: https://wordpress.org/plugins/wp-password-policy-manager/
  Description: Update password with password policy when create user by administrator
  Author: Kulka Nicolas
  Author URI: http://nicolaskulka.fr/
  Version: 1.0
  Text Domain: nk-pwd-policy
 */

class NK_Password_Policy {
	/**
	 * Constructor, register hooks !
	 */
	public function __construct() {
		add_filter( 'random_password', array( __CLASS__, 'random_password' ) );
		add_action( 'retrieve_password', array( __CLASS__, 'retrieve_password') );
	}

	/**
	 * Hook WP random_password for generate valid password
	 * @param $password
	 *
	 * @return string
	 */
	public static function random_password( $password ) {
		if ( ! class_exists( 'WpPasswordPolicyManager' ) ) {
			return $password;
		}

		$p_policy = WpPasswordPolicyManager::GetInstance();

		$password = self::generate_password( $p_policy->GetPasswordLen(), $p_policy );

		return $password;
	}

	/**
	 *
	 * Hook WP retrieve_password for generate key walid password for reset password
	 * without password policy
	 *
	 * @param $user_login
	 */
	public static function retrieve_password($user_login) {
		remove_filter('random_password', array( __CLASS__, 'random_password' ));
	}

	/**
	 * Try to generate a password valid VS password policy
	 *
	 * @param $password_length
	 * @param WpPasswordPolicyManager $p_policy
	 *
	 * @return string
	 */
	public static function generate_password( $password_length, WpPasswordPolicyManager $p_policy ) {
		$characters = "abcdefghijklmnopqrstuwxyz";

		if ( $p_policy->IsPolicyEnabled( $p_policy::POLICY_MIXCASE ) ) {
			$characters .= "ABCDEFGHIJKLMNOPQRSTUWXYZ";
		}

		if ( $p_policy->IsPolicyEnabled( $p_policy::POLICY_NUMBERS ) ) {
			$characters .= "0123456789";
		}

		if ( $p_policy->IsPolicyEnabled( $p_policy::POLICY_SPECIAL ) ) {
			$characters .= "~!@#$%^&*()-_=+[]{};:,.<>/?";
		}

		do {
			$pass            = array(); //remember to declare $pass as an array
			$characters_size = strlen( $characters ) - 1; //put the length -1 in cache
			for ( $i = 0; $i < $password_length; $i ++ ) {
				$n = mt_rand( 0, $characters_size );

				$pass[] = $characters[ $n ];
			}

			$new_password       = implode( '', $pass );
			$new_password_check = self::check_password_policy( $new_password, $p_policy );
		} while ( is_wp_error( $new_password_check ) );

		return $new_password;
	}

	/**
	 * Check that new password is valid VS policy
	 *
	 * @param $password
	 * @param WpPasswordPolicyManager $p_policy
	 *
	 * @return bool|WP_Error
	 */
	public static function check_password_policy( $password, WpPasswordPolicyManager $p_policy ) {
		if ( ( $c = $p_policy->GetPasswordLen() ) != 0 ) {
			if ( strlen( $password ) < $c ) {
				return new WP_Error( 'expired_password', sprintf( __( '<strong>ERROR</strong>: New password must contain at least %d characters.', 'wp-password-policy-manager' ), $c ) );
			}
		}
		if ( $p_policy->IsPolicyEnabled( $p_policy::POLICY_MIXCASE ) ) {
			if ( strtolower( $password ) == $password ) {
				return new WP_Error( 'expired_password', __( '<strong>ERROR</strong>: New password must contain both uppercase and lowercase characters.', 'wp-password-policy-manager' ) );
			}
		}
		if ( $p_policy->IsPolicyEnabled( $p_policy::POLICY_NUMBERS ) ) {
			if ( ! preg_match( '/[0-9]/', $password ) ) {
				return new WP_Error( 'expired_password', __( '<strong>ERROR</strong>: New password must contain numbers.', 'wp-password-policy-manager' ) );
			}
		}
		if ( $p_policy->IsPolicyEnabled( $p_policy::POLICY_SPECIAL ) ) {
			if ( ! preg_match( '/[_\W]/', $password ) ) {
				return new WP_Error( 'expired_password', __( '<strong>ERROR</strong>: New password must contain special characters.', 'wp-password-policy-manager' ) );
			}
		}

		return true;
	}
}

new NK_Password_Policy();