<?php

class AWSSignedURL_Options
{

  public function __construct() {
    add_action('admin_menu', array($this, 'aws_signed_url_add_admin_menu'));
    add_action('admin_init', array($this, 'aws_signed_url_settings_init'));
  }


  function aws_signed_url_add_admin_menu() : void {
    add_options_page(__('AWS Signed URL'), __('AWS Signed URL'), 'manage_options', 'aws_signed_url', array($this,'aws_signed_url_options_page'));
  }


  function aws_signed_url_settings_init() : void {

    register_setting('aws_signed_url_pluginPage', 'aws_signed_url_settings', array($this, 'validate_input'));

    add_settings_section(
      'aws_signed_url_pluginPage_section',
      __('CloudFront Key Pair Details', 'wordpress'),
      array($this,'aws_signed_url_settings_section_callback'),
      'aws_signed_url_pluginPage'
    );

    add_settings_field(
      'aws_signed_url_key_pair_id',
      __('CloudFront Key Pair ID', 'wordpress'),
      array($this, 'aws_signed_url_key_pair_id_render'),
      'aws_signed_url_pluginPage',
      'aws_signed_url_pluginPage_section'
    );

    add_settings_field(
      'aws_signed_url_pem',
      __('Private Key PEM', 'wordpress'),
      array($this, 'aws_signed_url_pem_render'),
      'aws_signed_url_pluginPage',
      'aws_signed_url_pluginPage_section'
    );

    add_settings_field(
      'aws_signed_url_lifetime',
      __('URL Lifetime', 'wordpress'),
      array($this, 'aws_signed_url_lifetime_render'),
      'aws_signed_url_pluginPage',
      'aws_signed_url_pluginPage_section'
    );

  }


  function aws_signed_url_key_pair_id_render() : void {
    $options = get_option('aws_signed_url_settings');
    echo "<input type='text' size='25' name='aws_signed_url_settings[aws_signed_url_key_pair_id]' value='{$options['aws_signed_url_key_pair_id']}' />";
  }


  function aws_signed_url_pem_render() : void {
    $options = get_option('aws_signed_url_settings');
    echo "<input type='text' size='50' style='font-family:Consolas,Monaco,Lucida Console,Liberation Mono,DejaVu Sans Mono,Bitstream Vera Sans Mono,Courier New, monospaced;' name='aws_signed_url_settings[aws_signed_url_pem]' value='{$options['aws_signed_url_pem']}' />";
  }


  function aws_signed_url_settings_section_callback() : void {
    echo __('Set the Key Pair ID and the Private key file path for creating AWS Signed URLs');
  }

  function aws_signed_url_lifetime_render() : void {
    $options = get_option('aws_signed_url_settings');
    if (is_array( $options ) && !array_key_exists('aws_signed_url_lifetime', $options)){
      $options['aws_signed_url_lifetime'] = '5';
    }
    echo "<input type='number' min='1' max='20000' name='aws_signed_url_settings[aws_signed_url_lifetime]' value='{$options['aws_signed_url_lifetime']}'</input> Minutes";
  }

  function aws_signed_url_options_page() : void {
    echo <<< START
    <form action='options.php' method='post'>
    <h2>AWS Signed URL</h2>
    <p>To create CloudFront signed URLs your trusted signer must have its own CloudFront key pair,
     and the key pair must be active. For details see
    <a href=http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PrivateContent.html>Serving Private Content through CloudFront</a>
    </p><p>For security reasons, place your private key file above the root folder of your website, and specify the file path here.</p>
START;
    settings_fields('aws_signed_url_pluginPage');
    do_settings_sections('aws_signed_url_pluginPage');
    submit_button();


    echo "</form>";
  }

  function validate_input($input) {
    // Create our array for storing the validated options
    $input['aws_signed_url_key_pair_id'] = trim($input['aws_signed_url_key_pair_id']);
    $input['aws_signed_url_pem'] = trim($input['aws_signed_url_pem']);

    if (strlen($input['aws_signed_url_key_pair_id']) == 0) {
      add_settings_error('aws_signed_url_key_pair_id', '' ,'Key Pair ID must be set', 'error');
    }

    if (strlen($input['aws_signed_url_pem']) == 0) {
      add_settings_error('aws_signed_url_pem', '' ,'Private Key must be set', 'error');
    } else {
	  $fp = fopen($input['aws_signed_url_pem'], "r");
	  if ($fp) {
		$priv_key = fread($fp, 2048);
		fclose($fp);
		$key = openssl_get_privatekey($priv_key);
        if (!$key) {
          add_settings_error('aws_signed_url_pem', '', 'Cannot parse Private Key. OpenSSL error: ' . openssl_error_string(), 'error');
        }
	  }
    }
    return $input;
  }
}
