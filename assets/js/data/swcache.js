const resource = [ /* --- CSS --- */ '/assets/css/style.css', /* --- PWA --- */ '/app.js', '/sw.js', /* --- HTML --- */ '/index.html', '/404.html', '/categories/', '/tags/', '/archives/', '/about/', /* --- Favicons & compressed JS --- */ '/assets/img/favicons/HackTheBox/1.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/AD_installation.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/AD_users.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/Interface-SRV-1.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/SRV-1-To-Kali.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/WIN-R.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/add_users2Ou.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/bob_login.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/clinet_1_01.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/creating_domain.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/diagram_02.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/diagram_03.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/dns_clinet1.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/firewall-SRV-1.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/get-addomain.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/gpo.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/info_domain.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/interface_config_01.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/interface_config_02.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/interface_config_03.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/interface_config_04.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/join_to_domain.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/kali-To-SRV-1.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/lab_01.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/powershell.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/setup_account.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/shared_folder_perm.png', '/assets/img/favicons/HackTheBox/ADDC-LAB/verify_the_machine.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/ADDC-LDAP3.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/SASL_ldap3.drawio.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/add_group_to_ou.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/add_user_to_ou.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/delete_atributes_users.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/ldap_ssl.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/not_secure_ldap.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/rename_user.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/search_for_users.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/update_user_attributes.png', '/assets/img/favicons/HackTheBox/ADDC-LDAP3/user4_permission.png', '/assets/img/favicons/HackTheBox/Derailed/1.png', '/assets/img/favicons/HackTheBox/Derailed/10.png', '/assets/img/favicons/HackTheBox/Derailed/11.png', '/assets/img/favicons/HackTheBox/Derailed/12.png', '/assets/img/favicons/HackTheBox/Derailed/13.png', '/assets/img/favicons/HackTheBox/Derailed/14.png', '/assets/img/favicons/HackTheBox/Derailed/15.png', '/assets/img/favicons/HackTheBox/Derailed/16.png', '/assets/img/favicons/HackTheBox/Derailed/17.png', '/assets/img/favicons/HackTheBox/Derailed/18.png', '/assets/img/favicons/HackTheBox/Derailed/19.png', '/assets/img/favicons/HackTheBox/Derailed/2.png', '/assets/img/favicons/HackTheBox/Derailed/3.png', '/assets/img/favicons/HackTheBox/Derailed/4.png', '/assets/img/favicons/HackTheBox/Derailed/5.png', '/assets/img/favicons/HackTheBox/Derailed/6.png', '/assets/img/favicons/HackTheBox/Derailed/7.png', '/assets/img/favicons/HackTheBox/Derailed/8.png', '/assets/img/favicons/HackTheBox/Derailed/9.png', '/assets/img/favicons/HackTheBox/Derailed/Derailed.png', '/assets/img/favicons/HackTheBox/Derailed/poc.mp4', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/1.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/2.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/3.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/4.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/5.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/6.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/7.png', '/assets/img/favicons/HackTheBox/HTB%20Season%201/inject/Inject.png', '/assets/img/favicons/HackTheBox/HighTech-cover.png', '/assets/img/favicons/HackTheBox/HighTech-profile.png', '/assets/img/favicons/HackTheBox/How%20ToMake%20a%20Simple%20Trojan%20with%20Python%20.png', '/assets/img/favicons/HackTheBox/How%20to%20Extract%20Chrome%20Passwords%20in%20Python.jpg', '/assets/img/favicons/HackTheBox/Inject.png', '/assets/img/favicons/HackTheBox/My%20logo%20Hd.png', '/assets/img/favicons/HackTheBox/Port%20scanner.png', '/assets/img/favicons/HackTheBox/Sandworm/Sandworm.png', '/assets/img/favicons/HackTheBox/Sandworm/contact.png', '/assets/img/favicons/HackTheBox/Sandworm/emsec_sandworm.png', '/assets/img/favicons/HackTheBox/Sandworm/firejail.png', '/assets/img/favicons/HackTheBox/Sandworm/flask.png', '/assets/img/favicons/HackTheBox/Sandworm/guide.png', '/assets/img/favicons/HackTheBox/Sandworm/home.png', '/assets/img/favicons/HackTheBox/Sandworm/how-does-pgp-encryption-work.webp', '/assets/img/favicons/HackTheBox/Sandworm/login.png', '/assets/img/favicons/HackTheBox/Sandworm/pspy64-1.png', '/assets/img/favicons/HackTheBox/Sandworm/pspy64.png', '/assets/img/favicons/HackTheBox/Sandworm/result.png', '/assets/img/favicons/HackTheBox/Sandworm/ssti_1.png', '/assets/img/favicons/HackTheBox/Sandworm/ssti_2.png', '/assets/img/favicons/HackTheBox/Sandworm/ssti_payload.png', '/assets/img/favicons/HackTheBox/Sandworm/verify_signature.png', '/assets/img/favicons/HackTheBox/Sau/Sau.png', '/assets/img/favicons/HackTheBox/Sau/gtfobins.png', '/assets/img/favicons/HackTheBox/Sau/root.png', '/assets/img/favicons/HackTheBox/Sau/shell.png', '/assets/img/favicons/HackTheBox/Sau/vulnerable_version.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_01.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_02.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_03.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_04.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_05.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_06.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_07.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_08.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_09.png', '/assets/img/favicons/HackTheBox/Sau/web_basket_10.png', '/assets/img/favicons/HackTheBox/Sekhmet.png', '/assets/img/favicons/HackTheBox/Sekhmet/1.png', '/assets/img/favicons/HackTheBox/Sekhmet/10.png', '/assets/img/favicons/HackTheBox/Sekhmet/11.png', '/assets/img/favicons/HackTheBox/Sekhmet/12.png', '/assets/img/favicons/HackTheBox/Sekhmet/13.png', '/assets/img/favicons/HackTheBox/Sekhmet/14.png', '/assets/img/favicons/HackTheBox/Sekhmet/15.png', '/assets/img/favicons/HackTheBox/Sekhmet/16.png', '/assets/img/favicons/HackTheBox/Sekhmet/17.png', '/assets/img/favicons/HackTheBox/Sekhmet/18.png', '/assets/img/favicons/HackTheBox/Sekhmet/19.png', '/assets/img/favicons/HackTheBox/Sekhmet/2.png', '/assets/img/favicons/HackTheBox/Sekhmet/21.png', '/assets/img/favicons/HackTheBox/Sekhmet/22.png', '/assets/img/favicons/HackTheBox/Sekhmet/23.png', '/assets/img/favicons/HackTheBox/Sekhmet/24.png', '/assets/img/favicons/HackTheBox/Sekhmet/25.png', '/assets/img/favicons/HackTheBox/Sekhmet/26.png', '/assets/img/favicons/HackTheBox/Sekhmet/27.png', '/assets/img/favicons/HackTheBox/Sekhmet/28.png', '/assets/img/favicons/HackTheBox/Sekhmet/29.png', '/assets/img/favicons/HackTheBox/Sekhmet/3.png', '/assets/img/favicons/HackTheBox/Sekhmet/30.png', '/assets/img/favicons/HackTheBox/Sekhmet/31.png', '/assets/img/favicons/HackTheBox/Sekhmet/32.png', '/assets/img/favicons/HackTheBox/Sekhmet/33.png', '/assets/img/favicons/HackTheBox/Sekhmet/34.png', '/assets/img/favicons/HackTheBox/Sekhmet/35.png', '/assets/img/favicons/HackTheBox/Sekhmet/36.png', '/assets/img/favicons/HackTheBox/Sekhmet/37.png', '/assets/img/favicons/HackTheBox/Sekhmet/38.png', '/assets/img/favicons/HackTheBox/Sekhmet/39.png', '/assets/img/favicons/HackTheBox/Sekhmet/4.png', '/assets/img/favicons/HackTheBox/Sekhmet/40.png', '/assets/img/favicons/HackTheBox/Sekhmet/41.png', '/assets/img/favicons/HackTheBox/Sekhmet/42.png', '/assets/img/favicons/HackTheBox/Sekhmet/43.png', '/assets/img/favicons/HackTheBox/Sekhmet/44.png', '/assets/img/favicons/HackTheBox/Sekhmet/45.png', '/assets/img/favicons/HackTheBox/Sekhmet/46.png', '/assets/img/favicons/HackTheBox/Sekhmet/47.png', '/assets/img/favicons/HackTheBox/Sekhmet/48.png', '/assets/img/favicons/HackTheBox/Sekhmet/49.png', '/assets/img/favicons/HackTheBox/Sekhmet/5.png', '/assets/img/favicons/HackTheBox/Sekhmet/50.png', '/assets/img/favicons/HackTheBox/Sekhmet/51.png', '/assets/img/favicons/HackTheBox/Sekhmet/52.png', '/assets/img/favicons/HackTheBox/Sekhmet/53.png', '/assets/img/favicons/HackTheBox/Sekhmet/6.png', '/assets/img/favicons/HackTheBox/Sekhmet/7.png', '/assets/img/favicons/HackTheBox/Sekhmet/8.png', '/assets/img/favicons/HackTheBox/Sekhmet/Sekhmet.png', '/assets/img/favicons/HackTheBox/Sekhmet/emsec.gif', '/assets/img/favicons/HackTheBox/emSec.png', '/assets/img/favicons/HackTheBox/emSec02.gif', '/assets/img/favicons/HackTheBox/emSec_cover.jpg', '/assets/img/favicons/HackTheBox/emsec_1.png', '/assets/img/favicons/HackTheBox/emsec_2.gif', '/assets/img/favicons/HackTheBox/emsec_3.gif', '/assets/img/favicons/HackTheBox/emsec_4.gif', '/assets/img/favicons/HackTheBox/emsec_5.gif', '/assets/img/favicons/HackTheBox/emsec_6.jpg', '/assets/img/favicons/HackTheBox/emsec_7.gif', '/assets/img/favicons/HackTheBox/emsec_cover2.jpg', '/assets/img/favicons/HackTheBox/emsec_pack.jpg', '/assets/img/favicons/HackTheBox/emsec_pack2.jpg', '/assets/img/favicons/HackTheBox/emsec_pack_1.jpg', '/assets/img/favicons/HackTheBox/htb_wallpaper.jpg', '/assets/img/favicons/android-icon-144x144.png', '/assets/img/favicons/android-icon-192x192.png', '/assets/img/favicons/android-icon-36x36.png', '/assets/img/favicons/android-icon-48x48.png', '/assets/img/favicons/android-icon-72x72.png', '/assets/img/favicons/android-icon-96x96.png', '/assets/img/favicons/apple-icon-114x114.png', '/assets/img/favicons/apple-icon-120x120.png', '/assets/img/favicons/apple-icon-144x144.png', '/assets/img/favicons/apple-icon-152x152.png', '/assets/img/favicons/apple-icon-180x180.png', '/assets/img/favicons/apple-icon-57x57.png', '/assets/img/favicons/apple-icon-60x60.png', '/assets/img/favicons/apple-icon-72x72.png', '/assets/img/favicons/apple-icon-76x76.png', '/assets/img/favicons/apple-icon-precomposed.png', '/assets/img/favicons/apple-icon.png', '/assets/img/favicons/favicon-16x16.png', '/assets/img/favicons/favicon-32x32.png', '/assets/img/favicons/favicon-96x96.png', '/assets/img/favicons/favicon.ico', '/assets/img/favicons/ms-icon-144x144.png', '/assets/img/favicons/ms-icon-150x150.png', '/assets/img/favicons/ms-icon-310x310.png', '/assets/img/favicons/ms-icon-70x70.png', '/assets/img/favicons/android-chrome-192x192.png', '/assets/img/favicons/android-chrome-512x512.png', '/assets/img/favicons/apple-touch-icon.png', '/assets/img/favicons/mstile-150x150.png', '/assets/js/dist/categories.min.js', '/assets/js/dist/commons.min.js', '/assets/js/dist/misc.min.js', '/assets/js/dist/page.min.js', '/assets/js/dist/post.min.js' ]; /* The request url with below domain will be cached */ const allowedDomains = [ '', 'fonts.gstatic.com', 'fonts.googleapis.com', 'cdn.jsdelivr.net', 'polyfill.io' ]; /* Requests that include the following path will be banned */ const denyUrls = [ ];
