discover_vhosts_via_bing
======================== 

Sızma testlerinin ilk adımı olarak hedef sisteme ait IP adres ve üzerinde koşan servislerin tespit edilmesi gelmektedir. Özellikle  uygulama güvenliği ile ilgilenen kişiler için hedef uygulamaların keşfi önemli bir yer arz etmektedir.
Bing Microsoft tarafından hizmet vermekte olan bir arama motoru sitesidir. Bing arama motoru sitesi sayesinden belirtilen IP adresi üzerinden hizmet vermekte olan sitelere erişim sağlanabilmektedir. Bu işlem ip:ip_adresi şeklinde bir belirtim ile gerçekleştirilebilmektedir. Internet üzerinde tek bir IP adresi için gerekli bu işlemi gerçekleştiren araçlar bulunmaktadır.
discover_vhosts_via_bing.py betigi ile belirtilen IP veya ağ için hizmet veren IP adreslerini Bing arama motoru üzerinden bulmaktadır. Betiğe https://github.com/agguvenligi/araclar/blob/master/discover_vhosts_via_bing.py adresinden erişim sağlanabilmektedir.

Kullanim: ./discover_vhosts_via_bing.py 173.194.112.81/30 5

          173.194.112.80 : scholar.google.com

          173.194.112.80 : scholar.google.it

          173.194.112.80 : scholar.google.dk

          173.194.112.80 : scholar.google.pt

          173.194.112.80 : afp.google.com

          ...
          ...

Betikle ilgili blog yazisina http://www.agguvenligi.net/2013/06/sanal-adreslemeli-web-sunucularin-bing-arama-motoru-ile-kesif-araci.html adresinden erisim saglanabilmektedir.

