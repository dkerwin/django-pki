$(document).ready( function() {
    
    // Update the CA clock
    UpdateTime();
    setInterval(UpdateTime, 1000);

    // PKCS#12 passphrase verify if checkbox is found
    if ( $("input[id=id_pkcs12_encoded]") ) {
        
        $('#id_pkcs12_passphrase').bind("change keyup focus", { 'a': '#id_pkcs12_passphrase', 'b': '#id_pkcs12_passphrase_verify' }, onPfChange);
        $('#id_pkcs12_passphrase_verify').bind("change keyup focus", { 'a': '#id_pkcs12_passphrase', 'b': '#id_pkcs12_passphrase_verify' }, onPfChange);
    }
    
    // Determine action => add | change
    if ( window.__pki_add__ != 'True' ) {
        
        onActionChange();
        $("input[name=action]").change(onActionChange);
        
        // Enable all elements on submit
        $("form").submit(function() {
                            
                            // Add dummy passphrase to survive model validation in CA mode
                            if ( (! $("input[id=id_action_3]").attr("checked")) && (window.__pki_model__ == 'CertificateAuthority') ) {
                                
                                $("input[id=id_passphrase]").val('XXXXXXXXXXXXXXXXXXXXXXXXXX');
                            }
                            
                            // Remove disabled attribute
                            $('#certificateauthority_form :input:not(:submit), #certificate_form :input:not(:submit)').each( function( i, el ) {
                                            $(el).removeAttr("disabled");
                            });
        });
    }
    else {
        
        $("input[id=id_action_1]").attr("disabled", "disabled");
        $("input[id=id_action_2]").attr("disabled", "disabled");
        $("input[id=id_action_3]").attr("disabled", "disabled");
        
        // Make id_passphrase_verify as required as id_passphrase
        $("label[for=id_passphrase_verify]").addClass($("label[for=id_passphrase]").attr("class"));
        
        onParentChange();
        onCnChange();
        
        $("#id_parent").change(onParentChange);
        $('#id_common_name').bind("change keyup", onCnChange);
        
        // Passphrase verify
        $('#id_passphrase').bind("change keyup focus", { 'a': '#id_passphrase', 'b': '#id_passphrase_verify' }, onPfChange);
        $('#id_passphrase_verify').bind("change keyup focus", { 'a': '#id_passphrase', 'b': '#id_passphrase_verify' }, onPfChange);        
    }
});

function onActionChange() {
    
    // disable create - this is never an option
    $("input[id=id_action_0]").attr("disabled", "disabled");
    
    if ( $("input[id=id_action_0]").attr("checked") ) {
        
        // and set update active
        $("input[id=id_action_1]").attr("checked", "checked");
    }
    
    var enabled_fields = new Array();
    var inputs  = $('#certificateauthority_form :input:not(:submit), #certificate_form :input:not(:submit)');
    
    // Always enable description and encoding options
    enabled_fields['id_description'] = 1;
    enabled_fields['id_action_1'] = 1;
    enabled_fields['id_action_2'] = 1;
    enabled_fields['id_action_3'] = 1;
    
    if ( $("input[id=id_action_1]").attr("checked") ) { // Update: Only enable description and DER encoding
        
        // Remove required class from parent_passphrase
        $("label[for=id_parent_passphrase]").removeClass('required');
        
        // Set DER encoded parent to yellow
        enabled_fields['id_der_encoded'] = 1;
        $("input[id=id_der_encoded]").parent().parent().css('background-color', '#fffcaa');
        
        // Enable pkcs12 when it's a certificate
        if ( window.__pki_model__ == 'Certificate' ) {
            
            enabled_fields['id_pkcs12_encoded'] = 1;
            enabled_fields['id_pkcs12_passphrase'] = 1;
            enabled_fields['id_pkcs12_passphrase_verify'] = 1;
            $("input[id=id_pkcs12_encoded]").parent().parent().css('background-color', '#fffcaa');
        }
    }
    else if ( $("input[id=id_action_2]").attr("checked") ) { // Revoke: Only enable description and parent passphrase
        
        // Set class required on parent_passphrase
        $("label[for=id_parent_passphrase]").addClass('required');
        
        // Add id_parent_passphrase to enabled_fields
        enabled_fields['id_parent_passphrase'] = 1;
        
        // Set BG color for der_encoded to default
        $("input[id=id_der_encoded]").parent().parent().css('background-color', '#ffffff');
        
        // Disable pkcs12 BG when it's a certificate
        if ( window.__pki_model__ == 'Certificate' ) {
            
            $("input[id=id_pkcs12_encoded]").parent().parent().css('background-color', '#ffffff');
        }
    }
    else if ( $("input[id=id_action_3]").attr("checked") ) { // Renew: Enable almost anything
        
        // Wipe passphrase field
        $("input[id=id_passphrase]").val('');
        $("input[id=id_passphrase_verify]").val('');
        
        // Set class required on parent_passphrase
        $("label[for=id_parent_passphrase]").addClass('required');
        
        // Enable most of the fields 
        enabled_fields['id_country'] = 1;
        enabled_fields['id_state'] = 1;
        enabled_fields['id_locality'] = 1;
        enabled_fields['id_organization'] = 1;
        enabled_fields['id_OU'] = 1;
        enabled_fields['id_email'] = 1;
        enabled_fields['id_valid_days'] = 1;
        enabled_fields['id_passphrase'] = 1;
        enabled_fields['id_parent_passphrase'] = 1;
        
        // Set DER encoded parent to yellow
        enabled_fields['id_der_encoded'] = 1;
        $("input[id=id_der_encoded]").parent().parent().css('background-color', '#fffcaa');
        
        // Enable pkcs12 when it's a certificate
        if ( window.__pki_model__ == 'Certificate' ) {
            
            enabled_fields['id_purpose'] = 1;
            enabled_fields['id_subjaltname'] = 1;
            
            enabled_fields['id_pkcs12_encoded'] = 1;
            enabled_fields['id_pkcs12_passphrase'] = 1;
            enabled_fields['id_pkcs12_passphrase_verify'] = 1;
            $("input[id=id_pkcs12_encoded]").parent().parent().css('background-color', '#fffcaa');
        }
    }
    
    // Loop through all elements to enable from enabled_fields and disable the rest
    inputs.each( function( i, el ) {
        
        if ( ! enabled_fields[el.id] ) {
            
            $(el).attr("disabled", "disabled");
            $(el).css('background-color', '#F2F2F2');
        }
        else {
            
            $(el).removeAttr("disabled");
            $(el).css('background-color', '#fffcaa');
        }
    });    
}

function onParentChange() {
    
    var selected = $("#id_parent option:selected");
    
    if (selected.val() != '') {
        
        $("#id_parent_passphrase").css('background-color', '#fffcaa');
        
        if ( $("#id_type option[value=SubCA]").length == 0 ) {
            
            $("#id_type").prepend('<option value="SubCA" selected="selected">SubCA</option>');
        }
        
        $("label[for=id_parent_passphrase]").addClass('required');
        $("#id_type option[value='RootCA']").remove();
    }
    else {
        
        $("#id_parent_passphrase").css('background-color', '#FFFFFF');
        
        if ( $("#id_type option[value=RootCA]").length == 0 ) {
            
            $("#id_type").prepend('<option value="RootCA" selected="selected">self-signed (RootCA)</option>');
        }
        
        $("label[for=id_parent_passphrase]").removeClass('required');
        $("#id_type option[value='SubCA']").remove();
    }
}

function onCnChange() {
    
    var cn_in  = $("#id_common_name").val();
    var cn_out = strFilter(cn_in);
    
    if (cn_in != '' && cn_out == '') {
        
        $("#id_name").css('background-color', '#fffcaa');
        $("#id_name").val('');
        
        if ( $("#no_valid_name").length == 0 ) {
            
            $("#id_name").after('<p id="no_valid_name"><font color="red"><strong>CommonName must contain at least one valid charcter (a-Z0-9)</strong></font></p>');
        };
    }
    else if (cn_out != '') {
        
        $("#id_name").css('background-color', '#d8fbd8');
        $("#id_name").css('color', '#000000');
        $("#id_name").val(cn_out);
        
        if ( $("#no_valid_name").length > 0 ) {
            
            $("#no_valid_name").remove();
        };
    }
    else {
        
        $("#id_name").css('background-color', '#FFFFFF');
        $("#id_name").val('');
    }
    return true;
}

function onPfChange(event) {
    
    var pf_1 = $(event.data.a).val();
    var pf_2 = $(event.data.b).val();
    
    var element_1 = $(event.data.a);
    var element_2 = $(event.data.b);
    
    var span_id   = 'pf_match_' + event.data.b.replace(/#/, '');
    var span_id_h = '#' + span_id;
    
    if ( pf_1.length > 0 || pf_2.length > 0 ) {
        
        if ( pf_1 != pf_2 ) {
            
            element_2.css('background-color', '#f15959');
            element_1.css('background-color', '#ffffff');
            
            if ( $(span_id_h).length > 0 ) {
                
                $(span_id_h).remove();
            }
            
            element_2.after('<span style="margin-left: 10px;" id="' + span_id + '"><img src="' + window.__admin_media_prefix__ + 'img/admin/icon-no.gif" />&nbsp;Mismatch</span>');
        }
        else {
            
            element_1.css('background-color', '#d8fbd8');
            element_2.css('background-color', '#d8fbd8');
            
            if ( $(span_id_h).length > 0 ) {
                
                $(span_id_h).remove();
            }
            
            element_2.after('<span style="margin-left: 10px;" id="' + span_id + '"><img src="' + window.__admin_media_prefix__ + 'img/admin/icon-yes.gif" />&nbsp;Match</span>');
        }
    }
    else {
        
        $(span_id_h).remove();
        element_1.css('background-color', '#ffffff');
        element_2.css('background-color', '#ffffff');
    }
}

function strFilter(string) {
    
    x = string.replace(/^\*/, 'asterisk');
    y = x.replace(/ /g, '_');
    return y.replace(/[^a-zA-Z0-9\-\_\.]/g,""); 
}

