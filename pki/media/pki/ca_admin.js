$(document).ready( function() {
    
    $(".details").hide();
    $(".switch").click(function() {
                            if ( $(this).attr("src") == "/static/pki/img/plus.png" ) {
                                var new_src = "/static/pki/img/minus.png";
                                $(this).next(".details").show();
                            }
                            else {
                                var new_src = "/static/pki/img/plus.png";
                                $(this).next(".details").hide();
                            }
                            
                            $(this).attr("src", new_src);});
    
    // Make passphrase look required
    $("label[for=id_passphrase]").addClass('required');
    
    var url = window.location.href.split("/");
    
    if ( url[url.length - 2] != "add" ) {
        
        onActionChange();
        $("input[name=action]").change(onActionChange);
        
        // Enable all elements on submit
        $("form").submit(function() {
                            
                            var $inputs = $('#certificateauthority_form input, #certificateauthority_form textarea, #certificateauthority_form select');
                            $inputs.each( function( i, el ) {
                                            $(el).removeAttr("disabled");
                            });
        });
    }
    else {
        
        $("input[id=id_action_1]").attr("disabled", "disabled");
        $("input[id=id_action_2]").attr("disabled", "disabled");
        $("input[id=id_action_3]").attr("disabled", "disabled");
        
        onParentChange();
        onCnChange();
        $("#id_parent").change(onParentChange);
        $('#id_common_name').bind("change keyup", onCnChange);
    }

});

function onActionChange() {
    
    // disable create - this is never an option
    $("input[id=id_action_0]").attr("disabled", "disabled");
    
    if ( $("input[id=id_action_0]").attr("checked") ) {
        
        // and set update active
        $("input[id=id_action_1]").attr("checked", "checked");
    }
    
    var $inputs = $('#certificateauthority_form input, #certificateauthority_form textarea, #certificateauthority_form select');
    
    // Enable and disable fields depending on the selected radio button
    $inputs.each( function( i, el ) {
                        
                        if ( el.name.search('^_') ) {
                            
                            // Update: Only enable description
                            if ( $("input[id=id_action_1]").attr("checked") ) {
                                
                                if ( ! el.id.match('id_action_[1-3]') ) {
                                    
                                    $("label[for=id_parent_passphrase]").addClass('required');
                                    
                                    if ( el.name == "description" ) {
                                        
                                        $(el).removeAttr("disabled");
                                        $(el).css('background-color', '#fffcaa');
                                        
                                    }
                                    else if ( el.name == "der_encoded" ) {
                                        
                                        $(el).removeAttr("disabled");
                                        $(el.parentNode.parentNode).css('background-color', '#fffcaa');
                                    }
                                    else {
                                        
                                        $(el).attr("disabled", "disabled");
                                        $(el).css('background-color', '#F2F2F2');
                                    }
                                }
                            }
                            // Revoke: All but parent_passphrase disabled
                            else if ( $("input[id=id_action_2]").attr("checked") ) {
                                
                                if ( ! el.id.match('id_action_[1-3]') ) {
                                    
                                    $("label[for=id_parent_passphrase]").addClass('required');
                                    
                                    if ( el.name == "der_encoded" ) {
                                        
                                        $(el).attr("disabled", "disabled");
                                        $(el.parentNode.parentNode).css('background-color', '#FFFFFF');
                                    }
                                    else if ( el.name == "subcas_allowed" ) {
                                        
                                        $(el).attr("disabled", "disabled");
                                        $(el.parentNode.parentNode).css('background-color', '#FFFFFF');
                                    }
                                    else if ( el.name != "parent_passphrase" ) {
                                        
                                        $(el).attr("disabled", "disabled");
                                        $(el).css('background-color', '#F2F2F2');
                                    }
                                    else {
                                        
                                        $(el).removeAttr("disabled", "disabled");
                                        $(el).css('background-color', '#fffcaa');
                                    }
                                }
                            }
                            // Renew: Cert settings are
                            else if ( $("input[id=id_action_3]").attr("checked") ) {
                                
                                var enabled_fields = new Array();
                                enabled_fields['description'] = 1;
                                enabled_fields['key_length'] = 1;
                                enabled_fields['valid_days'] = 1;
                                enabled_fields['passphrase'] = 1;
                                enabled_fields['parent_passphrase'] = 1;
                                enabled_fields['policy'] = 1;
                                enabled_fields['der_encoded'] = 1;
                                enabled_fields['subcas_allowed'] = 1;
                                
                                if ( ! el.id.match('id_action_[1-3]') ) {
                                    
                                    if ( ! enabled_fields[el.name] ) {
                                        
                                        $(el).css('background-color', '#F2F2F2');
                                        $(el).attr("disabled", "disabled");
                                    }
                                    else {
                                        
                                        $(el).removeAttr("disabled");
                                        $(el).attr("enabled", "enabled");
                                        
                                        if ( el.name == "der_encoded" ) {
                                            
                                            $(el.parentNode.parentNode).css('background-color', '#fffcaa');
                                        }
                                        else if ( el.name == "subcas_allowed" ) {
                                            
                                            $(el.parentNode.parentNode).css('background-color', '#fffcaa');
                                        }
                                        else {
                                            
                                            $(el).css('background-color', '#fffcaa');
                                        }
                                        
                                        if ( el.name == "passphrase" ) {
                                            
                                            $(el).val("");
                                        }
                                    }
                                }
                            }
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
            
            $("#no_valid_name").remove()
        };
    }
    else {
        
        $("#id_name").css('background-color', '#FFFFFF');
        $("#id_name").val('');
    }
    return true;
}

function strFilter(string) {
    
    x = string.replace(/^\*/, 'asterisk');
    y = x.replace(/ /g, '_');
    return y.replace(/[^a-zA-Z0-9\-\_\.]/g,""); 
}

