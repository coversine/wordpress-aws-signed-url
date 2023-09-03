<?php
defined( 'ABSPATH' ) OR exit;
/*
Plugin Name: AWS Signed URLs
Description: Generates signed urls for Cloudfront assets
Version: 1.0.2
Author: Cyril George

Copyright 2023 Coversine LLC
*/

register_activation_hook(   __FILE__, array( 'AWSSignedURL', 'aws_signed_url_activation' ) );
register_deactivation_hook(   __FILE__, array( 'AWSSignedURL', 'aws_signed_url_deactivation' ) );
register_uninstall_hook(    __FILE__, array( 'AWSSignedURL', 'aws_signed_url_uninstall' ) );

class AWSSignedURL
{

  protected static $instance;

  public static function init()
  {
      is_null( self::$instance ) AND self::$instance = new self;
      return self::$instance;
  }

  public function __construct()
  {
    add_shortcode('wpsign', array ($this, 'get_signed_URL_from_shortcode' ) );
	
	require_once(plugin_dir_path(__FILE__) . '/aws-signed-url-options.php');
    new AWSSignedURL_Options();

	add_filter('wp_get_attachment_url', array($this,'get_signed_URL'),100);
  }

  function get_signed_URL_from_shortcode($atts = array(), $content = null) 
  {
	$options = get_option('aws_signed_url_settings');
	// Extract the shortcode attributes
	$atts = shortcode_atts(
		array(
			'minutes' => $options['aws_signed_url_lifetime']
		),
		$atts
	);
    return self::get_signed_URL($content, $atts['minutes']);
  }

  // Create a Signed URL for media assets stored on S3 and served up via CloudFront
  function get_signed_URL($resource, $timeout) 
  {
	$options = get_option('aws_signed_url_settings');
	$url = "";
	if(!$timeout) {
		//get default timeout from settings
    	$timeout = $options['aws_signed_url_lifetime'];
	}

    $expires = time() + $timeout * 60; // Convert timeout to seconds
    $json = '{"Statement":[{"Resource":"'.$resource.'","Condition":{"DateLessThan":{"AWS:EpochTime":'.$expires.'}}}]}';

    // load the private key
    $fp = fopen($options['aws_signed_url_pem'], "r");
	if ($fp) {
		$priv_key = fread($fp, 2048);
		fclose($fp);
		$key = openssl_get_privatekey($priv_key);
		if(!$key)
		{
		  error_log( 'Failed to read private key: '.openssl_error_string() );
		  return $resource;
		}

		//Sign the policy with the private key
		if(!openssl_sign($json, $signed_policy, $key, OPENSSL_ALGO_SHA1))
		{
		  error_log( 'Failed to sign url: '.openssl_error_string());
		  return $resource;
		}

		//Create signiature
		$base64_signed_policy = base64_encode($signed_policy);
		$signature = str_replace(array('+','=','/'), array('-','_','~'), $base64_signed_policy);

		//Construct the URL
		$url = $resource.'?Expires='.$expires.'&Signature='.$signature.'&Key-Pair-Id='.$options['aws_signed_url_key_pair_id'];
	}
    return $url;
  }

  public static function aws_signed_url_activation() 
  {
    if ( ! current_user_can( 'activate_plugins' ) )
        return;
    $plugin = isset( $_REQUEST['plugin'] ) ? $_REQUEST['plugin'] : '';
    check_admin_referer( "activate-plugin_{$plugin}" );

    // Uncomment the following line to see the function in action
    // exit( var_dump( $_GET ) );
  }

  public static function aws_signed_url_deactivation() {
    if ( ! current_user_can( 'activate_plugins' ) )
        return;
    $plugin = isset( $_REQUEST['plugin'] ) ? $_REQUEST['plugin'] : '';
    check_admin_referer( "deactivate-plugin_{$plugin}" );

    // Uncomment the following line to see the function in action
    // exit( var_dump( $_GET ) );
  }

  public static function aws_signed_url_uninstall() {
    if ( ! current_user_can( 'activate_plugins' ) )
        return;
    check_admin_referer( 'bulk-plugins' );

    // Important: Check if the file is the one
    // that was registered during the uninstall hook.
    if ( __FILE__ != WP_UNINSTALL_PLUGIN )
        return;

    // Uncomment the following line to see the function in action
    // exit( var_dump( $_GET ) );
  }

}

AWSSignedURL::init();
