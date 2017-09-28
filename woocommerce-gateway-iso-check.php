<?php
/**
 * Plugin Name: WooCommerce ISO Check Gateway
 * Plugin URI: https://isodiol.com
 * Description: Isodiol custom E-Check gateway
 * Author: Isodiol
 * Author URI: http://isodiol.com/
 * Version: 1.0.0
 * Text Domain: wc-gateway-isocheck
 * Domain Path: /i18n/languages/
 *
 *
 * License: GNU General Public License v3.0
 * License URI: http://www.gnu.org/licenses/gpl-3.0.html
 *
 * @package   WC-Gateway-Isocheck
 * @author    Isodiol
 * @category  Admin\
 *
 * This Iso-Check gateway forks the WooCommerce core "Cheque" payment gateway to create another offline payment method.
 */
 
defined( 'ABSPATH' ) or exit;

// Make sure WooCommerce is active
if ( ! in_array( 'woocommerce/woocommerce.php', apply_filters( 'active_plugins', get_option( 'active_plugins' ) ) ) ) {
	return;
}


function iso_echeck_encrypt($plaintext) {
	if( !defined('ISO_ECHECK_KEY') )
		return $plaintext;
	$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
	$iv = openssl_random_pseudo_bytes($ivlen);
	$ciphertext_raw = openssl_encrypt($plaintext, $cipher, ISO_ECHECK_KEY, $options=OPENSSL_RAW_DATA, $iv);
	$hmac = hash_hmac('sha256', $ciphertext_raw, ISO_ECHECK_KEY, $as_binary=true);
	$ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
	return $ciphertext;
}

function iso_echeck_decrypt($ciphertext) {
	if( !defined('ISO_ECHECK_KEY') )
		return $ciphertext;
	$c = base64_decode($ciphertext);
	$ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
	$iv = substr($c, 0, $ivlen);
	$hmac = substr($c, $ivlen, $sha2len=32);
	$ciphertext_raw = substr($c, $ivlen+$sha2len);
	$original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, ISO_ECHECK_KEY, $options=OPENSSL_RAW_DATA, $iv);
	$calcmac = hash_hmac('sha256', $ciphertext_raw, ISO_ECHECK_KEY, $as_binary=true);
	if (hash_equals($hmac, $calcmac))//PHP 5.6+ timing attack safe comparison
	{
		return $original_plaintext;
	}
}

/**
 * Add the gateway to WC Available Gateways
 * 
 * @since 1.0.0
 * @param array $gateways all available WC gateways
 * @return array $gateways all WC gateways + isocheck gateway
 */
function wc_isocheck_add_to_gateways( $gateways ) {
	$gateways[] = 'WC_Gateway_Isocheck';
	return $gateways;
}
add_filter( 'woocommerce_payment_gateways', 'wc_isocheck_add_to_gateways' );


/**
 * Adds plugin page links
 * 
 * @since 1.0.0
 * @param array $links all plugin links
 * @return array $links all plugin links + our custom links (i.e., "Settings")
 */
function wc_isocheck_gateway_plugin_links( $links ) {

	$plugin_links = array(
		'<a href="' . admin_url( 'admin.php?page=wc-settings&tab=checkout&section=isocheck' ) . '">' . __( 'Configure', 'wc-isocheck-offline' ) . '</a>'
	);

	return array_merge( $plugin_links, $links );
}
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'wc_isocheck_gateway_plugin_links' );


/**
 * IsoCheck Payment Gateway
 *
 * Provides a custom E-Check Payment Gateway; mainly for testing purposes.
 * We load it later to ensure WC is loaded first since we're extending it.
 *
 * @class 		WC_Gateway_Isocheck
 * @extends		WC_Payment_Gateway
 * @version		1.0.0
 * @package		WooCommerce/Classes/Payment
 * @author 		SkyVerge
 */
add_action( 'plugins_loaded', 'wc_isocheck_gateway_init', 11 );

function wc_isocheck_gateway_init() {

	class WC_Gateway_Isocheck extends WC_Payment_Gateway {

		/**
		 * Constructor for the gateway.
		 */
		public function __construct() {
	  
			$this->id                 = 'isocheck';
			$this->id_dash			  = 'isocheck';
			$this->icon               = apply_filters('woocommerce_isocheck_icon', '');
			$this->has_fields         = false;
			
			// support default form with credit card
			$this->supports = array( 'payment_form_default_echeck_fields' );
			$this->method_title       = __( 'ISO eCheck', 'wc-gateway-isocheck' );
			$this->method_description = __( 'Allows E-Check payments. Orders are marked as "Pending Payment" when received.', 'wc-gateway-isocheck' );
			
			//$ISO_ECHECK_KEY = ISO_ECHECK_KEY;
			if( !defined('ISO_ECHECK_KEY') ) {
				$this->method_description .= "<div style='color:red;'><strong>WARNING!!! The encryption key is not defined in wp-config.php</strong>
				If the key is not defined bank account information will not be encrypted!
				<p>Add the following to wp-config.php:
				//ISO eCheck encryption key. ***If this is changed previously encypted data will be lost!!!!
				define( 'ISO_ECHECK_KEY', 'encryption key here');</p></div>";
			}
		  
			// Load the settings.
			$this->init_form_fields();
			$this->init_settings();
		  
			// Define user set variables
			$this->title        = $this->get_option( 'title' );
			$this->description  = $this->get_option( 'description' );
			$this->instructions = $this->get_option( 'instructions', $this->description );
		  
			// Actions
			add_action( 'woocommerce_update_options_payment_gateways_' . $this->id, array( $this, 'process_admin_options' ) );
			add_action( 'woocommerce_thankyou_' . $this->id, array( $this, 'thankyou_page' ) );
		  
			// Customer Emails
			add_action( 'woocommerce_email_before_order_table', array( $this, 'email_instructions' ), 10, 3 );
		}
	
	
		/**
		 * Initialize Gateway Settings Form Fields
		 */
		public function init_form_fields() {
	  
			$this->form_fields = apply_filters( 'wc_isocheck_form_fields', array(
		  
				'enabled' => array(
					'title'   => __( 'Enable/Disable', 'wc-gateway-isocheck' ),
					'type'    => 'checkbox',
					'label'   => __( 'Enable ISO Check Payment', 'wc-gateway-isocheck' ),
					'default' => 'no'
				),
				
				'title' => array(
					'title'       => __( 'Title', 'wc-gateway-isocheck' ),
					'type'        => 'text',
					'description' => __( 'This controls the title for the payment method the customer sees during checkout.', 'wc-gateway-isocheck' ),
					'default'     => __( 'eCheck Payment', 'wc-gateway-isocheck' ),
					'desc_tip'    => true,
				),
				
				'description' => array(
					'title'       => __( 'Description', 'wc-gateway-isocheck' ),
					'type'        => 'textarea',
					'description' => __( 'Payment method description that the customer will see on your checkout.', 'wc-gateway-isocheck' ),
					'default'     => __( 'Please enter your Bank information below. Orders will not ship until funds have cleared.', 'wc-gateway-isocheck' ),
					'desc_tip'    => true,
				),
				
				'instructions' => array(
					'title'       => __( 'Instructions', 'wc-gateway-isocheck' ),
					'type'        => 'textarea',
					'description' => __( 'Instructions that will be added to the thank you page and emails.', 'wc-gateway-offline' ),
					'default'     => 'Please allow up to 2 business days for us to process your eCheck Payment. Orders will ship when payment has been processed successfully.',
					'desc_tip'    => true,
				),
			) );
		}
	
	
		/**
		 * Output for the order received page.
		 */
		public function thankyou_page() {
			if ( $this->instructions ) {
				echo wpautop( wptexturize( $this->instructions ) );
			}
		}
	
	
		/**
		 * Add content to the WC emails.
		 *
		 * @access public
		 * @param WC_Order $order
		 * @param bool $sent_to_admin
		 * @param bool $plain_text
		 */
		public function email_instructions( $order, $sent_to_admin, $plain_text = false ) {
		
			if ( $this->instructions && ! $sent_to_admin && $this->id === $order->payment_method && $order->has_status( 'on-hold' ) ) {
				echo wpautop( wptexturize( $this->instructions ) ) . PHP_EOL;
			}
		}
		
		public function payment_fields(){

            if ( $description = $this->get_description() ) {
                echo wpautop( wptexturize( $description ) );
            }
			?>
           <div class="iso-payment-gateway-echeck-form-sample-check"><img id="iso-sample-check" src="<?=esc_url( plugins_url( '/sample-check.png', __FILE__ ) )?>" /></div><div style="margin:2em auto;">
           <?php
            $this->render_payment_fields();
			echo "</div>";
        }
	
	/**
	 * Get default eCheck form fields, note this pulls default values
	 * from the associated gateway
	 *
	 * @since 4.0.0
	 * @return array eCheck form fields
	 */
	protected function get_payment_fields() {

		$check_hint = sprintf( '<img title="%s" class="iso-payment-gateway-echeck-form-check-hint" src="%s" width="16" height="16" onClick="toggleSampleCheck()" />', esc_attr__( 'Where do I find this?', 'woocommerce-plugin-framework' ), esc_url( WC()->plugin_url() . '/assets/images/help.png' ) );

		$fields = array(
			'routing-number' => array(
				'type'              => 'tel',
				/* translators: e-check routing number, HTML form field label, https://en.wikipedia.org/wiki/Routing_transit_number */
				'label'             => esc_html__( 'Routing Number', 'woocommerce-plugin-framework' ) . $check_hint,
				'id'                => 'wc-' . $this->id_dash . '-routing-number',
				'name'              => 'wc-' . $this->id_dash . '-routing-number',
				'placeholder'       => '•••••••••',
				'required'          => true,
				'class'             => array( 'form-row-first' ),
				'input_class'       => array( 'js-sv-wc-payment-gateway-echeck-form-input js-sv-wc-payment-gateway-echeck-form-routing-number' ),
				'maxlength'         => 9,
				'custom_attributes' => array(
					'autocomplete'   => 'off',
					'autocorrect'    => 'no',
					'autocapitalize' => 'no',
					'spellcheck'     => 'no',
				),
				'value'             => '',
			),
			'account-number' => array(
				'type'              => 'tel',
				/* translators: e-check account number, HTML form field label */
				'label'             => esc_html__( 'Account Number', 'woocommerce-plugin-framework' ) . $check_hint,
				'id'                => 'wc-' . $this->id_dash . '-account-number',
				'name'              => 'wc-' . $this->id_dash . '-account-number',
				'required'          => true,
				'class'             => array( 'form-row-last' ),
				'input_class'       => array( 'js-sv-wc-payment-gateway-echeck-form-input js-sv-wc-payment-gateway-echeck-form-account-number' ),
				'maxlength'         => 17,
				'custom_attributes' => array(
					'autocomplete'   => 'off',
					'autocorrect'    => 'no',
					'autocapitalize' => 'no',
					'spellcheck'     => 'no',
				),
				'value'             => '',
			),
			'account-type'   => array(
				'type'              => 'select',
				/* translators: e-check account type, HTML form field label */
				'label'             => esc_html__( 'Account Type', 'woocommerce-plugin-framework' ),
				'id'                => 'wc-' . $this->id_dash . '-account-type',
				'name'              => 'wc-' . $this->id_dash . '-account-type',
				'required'          => true,
				'class'             => array( 'form-row-wide' ),
				'input_class'       => array( 'js-sv-wc-payment-gateway-echeck-form-input js-sv-wc-payment-gateway-echeck-form-account-type' ),
				'options'           => array(
					/* translators: http://www.investopedia.com/terms/c/checkingaccount.asp  */
					'checking' => esc_html_x( 'Checking', 'account type', 'woocommerce-plugin-framework' ),
					/* translators: http://www.investopedia.com/terms/s/savingsaccount.asp  */
					'savings'  => esc_html_x( 'Savings',  'account type', 'woocommerce-plugin-framework' ),
				),
				'custom_attributes' => array(),
				'value'             => 'checking',
			),
		);

		/**
		 * Payment Gateway Payment Form Default eCheck Fields.
		 *
		 * Filters the default field data for eCheck gateways.
		 *
		 * @since 4.0.0
		 * @param array $fields in the format supported by woocommerce_form_fields()
		 * @param \SV_WC_Payment_Gateway_Payment_Form $this payment form instance
		 */
		return $fields;
	}
		
			/**
	 * Render the payment fields (e.g. account number, expiry, etc)
	 *
	 * @hooked wc_{gateway ID}_payment_form_start @ priority 0
	 *
	 * @since 4.0.0
	 */
	public function render_payment_fields() {

		foreach ( $this->get_payment_fields() as $field ) {
			$this->render_payment_field( $field );
		}
	}


	/**
	 * Render the payment, a simple wrapper around woocommerce_form_field() to
	 * make it more convenient for concrete gateways to override form output
	 *
	 * @since 4.1.2
	 * @param array $field
	 */
	protected function render_payment_field( $field ) {

		woocommerce_form_field( $field['name'], $field, $field['value'] );
	}
	
		/**
		 * Process the payment and return the result
		 *
		 * @param int $order_id
		 * @return array
		 */
		public function process_payment( $order_id ) {
	
			$order = wc_get_order( $order_id );
			
			// Mark as on-hold (we're awaiting the payment)
			$order->update_status( 'pending', __( 'Awaiting E-Check payment', 'wc-gateway-isocheck' ) );
			
			// Reduce stock levels
			$order->reduce_order_stock();
			
			// Remove cart
			WC()->cart->empty_cart();
			
			// Return thankyou redirect
			return array(
				'result' 	=> 'success',
				'redirect'	=> $this->get_return_url( $order )
			);
		}
	
  } // end \WC_Gateway_Isocheck class
}

add_action('woocommerce_checkout_process', 'process_custom_payment');
function process_custom_payment(){

    if($_POST['payment_method'] != 'isocheck')
        return;

    if( !isset($_POST['wc-isocheck-routing-number']) || empty($_POST['wc-isocheck-routing-number']) )
        wc_add_notice( __( 'Please add your eCheck routing number', 'wc-gateway-isocheck' ), 'error' );

    if( !isset($_POST['wc-isocheck-account-number']) || empty($_POST['wc-isocheck-account-number']) )
        wc_add_notice( __( 'Please add your eCheck account number', 'wc-gateway-isocheck' ), 'error' );

    if( !isset($_POST['wc-isocheck-account-type']) || empty($_POST['wc-isocheck-account-type']) )
        wc_add_notice( __( 'Please add your eCheck accoutnt type', 'wc-gateway-isocheck' ), 'error' );


}

/**
 * Update the order meta with field value
 */
add_action( 'woocommerce_checkout_update_order_meta', 'isocheck_payment_update_order_meta' );
function isocheck_payment_update_order_meta( $order_id ) {

    if($_POST['payment_method'] != 'isocheck')
        return;

    update_post_meta( $order_id, '_isocheck_routing_number', iso_echeck_encrypt($_POST['wc-isocheck-routing-number']) );
    update_post_meta( $order_id, '_isocheck_account_number', iso_echeck_encrypt($_POST['wc-isocheck-account-number']) );
    update_post_meta( $order_id, '_isocheck_account_type', iso_echeck_encrypt($_POST['wc-isocheck-account-type']) );
}

/**
 * Display field value on the order edit page
 */
add_action( 'woocommerce_admin_order_data_after_shipping_address', 'isocheck_checkout_field_display_admin_order_meta', 10, 1 );
function isocheck_checkout_field_display_admin_order_meta($order){
	$order_id = $order->get_id();
    $method = get_post_meta( $order_id, '_payment_method', true );
    if($method != 'isocheck')
        return;
	if(!current_user_can('manage_woocommerce'))
		return;
	
    $routing_number = iso_echeck_decrypt(get_post_meta( $order_id, '_isocheck_routing_number', true ));
    $account_number = iso_echeck_decrypt(get_post_meta( $order_id, '_isocheck_account_number', true ));
    $account_type = iso_echeck_decrypt(get_post_meta( $order_id, '_isocheck_account_type', true ));

    echo '<h3>eCheck Information</h3><p><strong>'.__( 'Routing Number' ).':</strong> ' . $routing_number . '<br>';
    echo '<strong>'.__( 'Account Number').':</strong> ' . $account_number . '<br>';
    echo '<strong>'.__( 'Account Type').':</strong> ' . $account_type . '</p>';
}

add_action('wp_footer','add_iso_echeck_scripts_styles');
function add_iso_echeck_scripts_styles() {
	?>
<style>
	div.iso-payment-gateway-echeck-form-sample-check {
		margin: 2em auto;
		display: none;
	}
	div.iso-payment-gateway-echeck-form-sample-check img#iso-sample-check {
		max-height: none;
		max-width: none;
		width: 100%;
		height: auto;
		float: none;
	}
</style>
<script>
	function toggleSampleCheck() {
		jQuery('div.iso-payment-gateway-echeck-form-sample-check').slideToggle(250);
	}
</script>
<?php
}
