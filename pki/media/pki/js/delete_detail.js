$(document).ready( function() {
    
    // Hide details in delete view
    $(".details").hide();
    $(".switch").click(function() {
                            if ( $(this).attr("src") == MEDIA_URL + "pki/img/plus.png" ) {
                                var new_src = MEDIA_URL + "pki/img/minus.png";
                                $(this).next(".details").show();
                            }
                            else {
                                var new_src = MEDIA_URL + "pki/img/plus.png";
                                $(this).next(".details").hide();
                            }
                            
                            $(this).attr("src", new_src);});
});
