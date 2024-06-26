# Практика 1. Wireshark: HTTP
Эта работа исследует несколько аспектов протокола HTTP: базовое взаимодействие GET/ответ,
форматы сообщений HTTP, получение больших файлов HTML, получение файлов HTML со
встроенными объектами, а также проверку подлинности и безопасность HTTP.

Во всех заданиях (а также во всех следующих лабах) предполагается, что вы к своему ответу 
приложите **подтверждающий скрин** программы Wireshark (достаточно одного скрина на задание).

## Задание 1. Базовое взаимодействие HTTP GET/response (2 балла)

#### Подготовка
1. Запустите веб-браузер.
2. Запустите анализатор пакетов Wireshark, но пока не начинайте захват пакетов. Введите
   «http» в окне фильтра, чтобы позже в окне списка пакетов отображались только захваченные сообщения HTTP.
3. Подождите несколько секунд, а затем начните захват пакетов Wireshark.
4. Введите в браузере адрес: http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file1.html.  
   Ваш браузер должен отобразить очень простой однострочный HTML-файл.
5. Остановите захват пакетов Wireshark.

#### Вопросы
1. Использует ли ваш браузер HTTP версии 1.0 или 1.1? Какая версия HTTP работает на
   сервере?
   - Как мой браузер, так и сервер использует протокол HTTP версии 1.1. ![me_http_1.1](./me_http_1.1.png) ![server_http_1.1](./server_http_1.1.png)
2. Какие языки (если есть) ваш браузер может принимать? В захваченном сеансе какую еще
   информацию (если есть) браузер предоставляет серверу относительно пользователя/браузера?
   - Мой браузер может принимать только американский английский: ![lang_en_US](./lang_en_US.png)
   - Бразуер предоставляет данные о том, какой это браузер (Mozilla Firefox версии 123.0), об оконном менеджере X11, об операционной системе и архитектуре (Ubuntu Linux x86_64). Кроме того, говорится, что браузер использует движок Gecko (строка `Gecko/2010101`) версии 123.0 (строка `rv:123.0`). ![userAgent](./userAgent.png)
3. Какой IP-адрес вашего компьютера? Какой адрес сервера gaia.cs.umass.edu?
   - Мой адрес `192.168.1.121`.
   - Адрес сервера `128.119.245.12`.
   ![ip_addresses](./ip_addresses.png)
4. Какой код состояния возвращается с сервера на ваш браузер?
   - Вернулся код 200 -- всё ОК.
   ![200_OK](./200_OK.png)
5. Когда HTML-файл, который вы извлекаете, последний раз модифицировался на сервере?
   - Сегодня (22 февраля 2024 г.) в 06:59:01 по Гринвичу
    ![lastModified](./lastModified.png)
6. Сколько байтов контента возвращается вашему браузеру?
   - 128 байт (`Content-Length`).

## Задание 2. HTTP CONDITIONAL GET/response (2 балла)
Большинство веб-браузеров выполняют кэширование объектов и, таким образом, выполняют
условный GET при извлечении объекта HTTP. Прежде чем выполнять описанные ниже шаги, 
убедитесь, что кеш вашего браузера пуст.

#### Подготовка
1. Запустите веб-браузер и убедитесь, что кэш браузера очищен.
2. Запустите анализатор пакетов Wireshark.
3. Введите следующий URL-адрес в адресную строку браузера:
   http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file2.html.  
   Ваш браузер должен отобразить очень простой пятистрочный HTML-файл.
4. Введите тот же URL-адрес в браузер еще раз (или просто нажмите кнопку обновления в
   браузере).
5. Остановите захват пакетов Wireshark и введите «http» в окне фильтра, чтобы в окне списка
   пакетов отображались только захваченные HTTP-сообщения.

#### Вопросы
1. Проверьте содержимое первого HTTP-запроса GET. Видите ли вы строку «IF-MODIFIED-SINCE» в HTTP GET?
   - Нет. ![noIfModifiedSince](./noIfModifiedSince.png)
2. Проверьте содержимое ответа сервера. Вернул ли сервер содержимое файла явно? Как вы
   это можете увидеть?
   - Да, сервер вернул содержимое html-файла явно; это можно увидеть в hexdump'е ответа:
    ![2_fullResponse](./2_fullResponse.png)
3. Теперь проверьте содержимое второго HTTP-запроса GET (из вашего браузера на сторону
   сервера). Видите ли вы строку «IF-MODIFIED-SINCE» в HTTP GET? Если да, то какая
   информация следует за заголовком «IF-MODIFIED-SINCE»?
   - Да, во втором GET-запросе есть строка `If-Modified-Since`, после неё идёт дата `Last-Modified` html-страницы из предыдущего GET-запроса. Если файл на сервере был изменён после этой даты, то сервер вернёт содержимое нового файла. Иначе, он сообщит, что файл не менялся с этого момента.
   - *Сразу после мы видим строку `If-None-Match`. Судя по [этой странце](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match), `If-None-Match` (если его поддерживает сервер), имеет преимущество над `If-Modified-Since`. В этом случае, мы передаём ETag (хэш) содержимого серверу. Сервер сверяет его, и отправляет полностью файл, только если хэши не совпали.*
   ![2_yesIfModifiedSince](./2_yesIfModifiedSince.png)
4. Какой код состояния HTTP и фраза возвращаются сервером в ответ на этот второй запрос
   HTTP GET? Вернул ли сервер явно содержимое файла?
   - Сервер вернул в ответ код 304 "Not Modified", то есть файл всё-таки не был изменён.
   ![2_304_not_modified](./2_304_not_modified.png)
   - Сервер не вернул содержимое: мы не видим content-length и HTML-кода страницы.
   ![2_no_content](./2_no_content.png)

## Задание 3. Получение длинных документов (2 балла)

#### Подготовка
1. Запустите веб-браузер и убедитесь, что кэш браузера очищен.
2. Запустите анализатор пакетов Wireshark.
3. Введите следующий URL-адрес в адресную строку браузера:
   http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file3.html  
   В браузере должен отобразиться довольно длинный текст.
4. Остановите захват пакетов Wireshark и введите «http» в окне фильтра.

#### Вопросы
1. Сколько сообщений HTTP GET отправил ваш браузер? Какой номер пакета в трассировке
   содержит сообщение GET?
   - Браузер отправил один HTTP GET запрос. (Не считая второго запроса на `favicon.ico`, которого нет у сервера.)
   ![3_1_get_request](./3_1_get_request.png)
   - GET-запрос в пакете 51.
   ![3_frame_51](./3_frame_51.png)
2. Какой номер пакета в трассировке содержит код состояния и фразу, связанные с ответом
   на HTTP-запрос GET?
   - Пакет 53.
   ![3_frame_53](./3_frame_53.png)
3. Сколько сегментов TCP, содержащих данные, потребовалось для передачи одного HTTP ответа?
   - Один TCP сегмент.
   ![3_1_segment](./3_1_segment.png)
4. Есть ли в передаваемых данных какая-либо информация заголовка HTTP, связанная с
   сегментацией TCP?
   - Ничего нет.
   ![3_no_tcp](./3_no_tcp.png)

## Задание 4. HTML-документы со встроенными объектами (2 балла)
Исследуйте, что происходит, когда ваш браузер загружает файл со встроенными объектами, т. е. файл, 
включающий в себя другие объекты (в данном примере это файлы и картинки),
которые хранятся на другом сервере (серверах).

#### Подготовка
1. Запустите веб-браузер и убедитесь, что кэш браузера очищен.
2. Запустите анализатор пакетов Wireshark.
3. Введите следующий URL-адрес в адресную строку браузера:
   http://gaia.cs.umass.edu/wireshark-labs/HTTP-wireshark-file4.html.  
   Ваш браузер должен отобразить HTML-файл с двумя изображениями. На эти два изображения есть ссылки в
   базовом файле HTML. То есть сами изображения не содержатся в HTML, вместо этого URL-
   адреса изображений содержатся в загруженном файле HTML. Ваш браузер должен
   получить эти изображения с указанных веб-сайтов.
4. Остановите захват пакетов Wireshark и введите «http» в окне фильтра.

#### Вопросы
1. Сколько HTTP GET запросов было отправлено вашим браузером? На какие интернет-адреса были отправлены эти GET-запросы?
   - Не считая favicon.ico, браузер отправил три GET-запроса: один на саму HTML-страницу, и два запроса на каждую из картинок.
   ![4_three_requests](./4_three_requests.png)
   - Запрос на HTML-страницу и на картинку `pearson.png` был отправлен на адрес `http://gaia.cs.umass.edu` (IP `128.119.245.12`), а на картинку `BE_cover_small.jpg` запрос был отправлен на адрес `kurose.cslash.net` (IP `178.79.137.164`). (Та же картинка сверху).
2. Можете ли вы сказать, загрузил ли ваш браузер два изображения последовательно или
   они были загружены с веб-сайтов параллельно? Объясните.
   - Браузер загружал картинки параллельно, потому что оба запроса были отправлены до первого из ответов.

## Задание 5. HTTP-аутентификация (2 балла)
Запустите веб-сайт, защищенный паролем, и исследуйте последовательность HTTP-сообщений, которыми обмениваются такие сайты.

#### Подготовка
1. Убедитесь, что кеш вашего браузера очищен.
2. Запустите анализатор пакетов Wireshark.
3. Введите следующий URL-адрес в адресную строку браузера:
   http://gaia.cs.umass.edu/wireshark-labs/protected_pages/HTTP-wireshark-file5.html
4. Введите требуемые имя пользователя и пароль во всплывающем окне  
   (Имя пользователя — «wireshark-students», пароль — «network»).
5. Остановите захват пакетов Wireshark и введите «http» в окне фильтра

#### Вопросы
1. Каков ответ сервера (код состояния и фраза) в ответ на начальное HTTP-сообщение GET от вашего браузера?
   - 401 Unauthorized
   ![5_401](./5_401.png)
2. Когда ваш браузер отправляет сообщение HTTP GET во второй раз, какое новое поле включается в сообщение HTTP GET?
   - Новое поле `Authorization`, в нём мы видим логин и пароль. 
   ![5_auth](./5_auth.png)
