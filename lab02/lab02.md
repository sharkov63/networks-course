# Практика 2. Rest Service

## Программирование. Rest Service. Часть I

### Задание А (3 балла)
Создайте простой REST сервис, в котором используются HTTP операции GET, POST, PUT и DELETE.
Предположим, что это сервис для будущего интернет-магазина, который пока что умеет 
работать только со списком продуктов. У каждого продукта есть поля: `id` (уникальный идентификатор),
`name` и `description`. 

Таким образом, json-схема продукта (обозначим её `<product-json>`):

```json
{
  "id": 0,
  "name": "string",
  "description": "string"
}
```

Данные продукта от клиента к серверу должны слаться в теле запроса в виде json-а, **не** в параметрах запроса.

Ваш сервис должен поддерживать следующие операции:
1. Добавить новый продукт. При этом его `id` должен сгенерироваться автоматически
   - `POST /product`
   - Схема запроса:
     ```json
     {
       "name": "string",
       "description": "string"
     }
     ```
   - Схема ответа: `<product-json>` (созданный продукт)
2. Получить продукт по его id
   - `GET /product/{product_id}`
   - Схема ответа: `<product-json>`
3. Обновить существующий продукт (обновляются только те поля продукта, которые были переданы в теле запроса)
   - `PUT /product/{product_id}`
   - Схема запроса: `<product-json>` (некоторые поля могут быть опущены)
   - Схема ответа: `<product-json>` (обновлённый продукт)
4. Удалить продукт по его id
   - `DELETE /product/{product_id}`
   - Схема ответа: `<product-json>` (удалённый продукт)
5. Получить список всех продуктов 
   - `GET /products`  
   - Схема ответа:
     ```
     [ 
       <product-json-1>,
       <product-json-2>, 
       ... 
     ]
     ```

Предусмотрите возвращение ошибок (например, если запрашиваемого продукта не существует).

Вы можете положить код сервиса в отдельную директорию рядом с этим документом.

### Задание Б (3 балла)
Продемонстрируйте работоспособность сервиса с помощью программы Postman
(https://www.postman.com/downloads) и приложите соответствующие скрины, на которых указаны
запросы и ответы со стороны сервиса для **всех** его операций.

#### Демонстрация работы

* Запускаем сервер: ![B_demo_1](./images/B_demo_1.png)
* Добавим несколько продуктов:
  ![B_demo_2](./images/B_demo_2.png)
  ![B_demo_3](./images/B_demo_3.png)
  ![B_demo_4](./images/B_demo_4.png)
  ![B_demo_5](./images/B_demo_5.png)
* Если передать невалидный JSON или опустить необходимые поля, вернётся 400 Bad Request:
  ![B_demo_6](./images/B_demo_6.png)
  ![B_demo_7](./images/B_demo_7.png)
* Получим продукты по ID:
  ![B_demo_8](./images/B_demo_8.png)
  ![B_demo_9](./images/B_demo_9.png)
* Если ID неправильный, то получим 404 Not Found:
  ![B_demo_10](./images/B_demo_10.png)
* Поменяем в продукте 0 оба поля:
  ![B_demo_11](./images/B_demo_11.png)
* А в продукте 3 одно поле:
  ![B_demo_12](./images/B_demo_12.png)
* Если указать несовпадающий ID в JSON, передать невалидный JSON, получим 400 Bad Reqeust: 
  ![B_demo_13](./images/B_demo_13.png)
  ![B_demo_14](./images/B_demo_14.png)
* А если изменить по несуществующему ID, получим 404 Not Found:
  ![B_demo_15](./images/B_demo_15.png)
* Удалим продукт 1:
  ![B_demo_16](./images/B_demo_16.png)
* А если удалить его ещё раз, получим 404 Not Found, так как такого продукта уже нет:
  ![B_demo_17](./images/B_demo_17.png)
*  Наконец, выведем все продукты:
  ![B_demo_18](./images/B_demo_18.png)

### Задание В (4 балла)
Пусть ваш продукт также имеет иконку (небольшую картинку). Формат иконки (картинки) может
быть любым на ваш выбор. Для простоты будем считать, что у каждого продукта картинка одна.

Добавьте две новые операции:
1. Загрузить иконку:
   - `POST product/{product_id}/image`
   - Запрос содержит бинарный файл — изображение  
     <img src="images/post-image.png" width=500 />
2. Получить иконку:
   - `GET product/{product_id}/image`
   - В ответе передаётся только сама иконка  
     <img src="images/get-image.png" width=500 />

Измените операции в Задании А так, чтобы теперь схема продукта содержала сведения о загруженной иконке, например, имя файла или путь:
```json
"icon": "string"
```

#### Демонстрация работы

- Добавим продукт: ![](./images/C_demo_1.png)
- Добавим к нему картинку: ![](./images/C_demo_2.png)
- Запросим картинку продукта: ![](./images/C_demo_3.png)

---

_(*) В последующих домашних заданиях вам будет предложено расширить функционал данного сервиса._

## Задачи

### Задача 1 (2 балла)
Общая (сквозная) задержка прохождения для одного пакета от источника к приемнику по пути,
состоящему из $N$ соединений, имеющих каждый скорость $R$ (то есть между источником и
приемником $N - 1$ маршрутизатор), равна $d_{\text{сквозная}} = N \dfrac{L}{R}$
Обобщите данную формулу для случая пересылки количества пакетов, равного $P$.

#### Решение
- $d_{\text{сквозная}} =  (N + P - 1) \dfrac{L}{R}$. Каждый пакет идёт ровно за следующим, отставая ровно на $L/R$ времени. В момент времени $NL/R$ придёт первый пакет, в момент времени $(N+1)L/R$ --- второй, ..., в момент $(N+P-1)L/R$ --- последний.

### Задача 2 (2 балла)
Допустим, мы хотим коммутацией пакетов отправить файл с хоста A на хост Б. Между хостами установлены три
последовательных канала соединения со следующими скоростями передачи данных:
$R_1 = 200$ Кбит/с, $R_2 = 3$ Мбит/с и $R_3 = 2$ Мбит/с.
Сколько времени приблизительно займет передача на хост Б файла размером $5$ мегабайт?
Как это время зависит от размера пакета?

#### Решение

Общая скорость передачи данных равна наименьшой из скоростей каждого канала, то есть $R = 200$ Кбит/c. Тогда время передачи файла размера 5 МБ равно
$$
\frac{5 \text{ МБ}}{200 \text{ Кбит / c}} = \frac{5 \cdot 1024 \cdot 1024 \cdot 8 \text{ бит}}{200 \cdot 1000 \text{ бит / c}} \approx 209.7 \text{ с}.
$$

### Задача 3 (2 балла)
Предположим, что пользователи делят канал с пропускной способностью $2$ Мбит/с. Каждому
пользователю для передачи данных необходима скорость $100$ Кбит/с, но передает он данные
только в течение $20$ процентов времени использования канала. Предположим, что в сети всего $60$
пользователей. А также предполагается, что используется сеть с коммутацией пакетов. Найдите
вероятность одновременной передачи данных $12$ или более пользователями.

#### Решение
В каждой момент времени каждый пользователь, независимо от других, передаёт данные с вероятностью $1/5$, то есть число одновременно передающих данных пользователей распределено биномиально. Значит, вероятность того, что 12 или более будут передавать одновременно равна
$$
\sum_{i=12}^{60} \binom{60}{i} \frac 1 {5^i} \cdot \left( \frac45 \right)^{60 - i} \approx 0.5513825262506522
$$

### Задача 4 (2 балла)
Пусть файл размером $X$ бит отправляется с хоста А на хост Б, между которыми три линии связи и
два коммутатора. Хост А разбивает файл на сегменты по $S$ бит каждый и добавляет к ним
заголовки размером $80$ бит, формируя тем самым пакеты длиной $L = 80 + S$ бит. Скорость
передачи данных по каждой линии составляет $R$ бит/с. Загрузка линий мала, и очередей пакетов
нет. При каком значении $S$ задержка передачи файла между хостами А и Б будет минимальной?
Задержкой распространения сигнала пренебречь.

#### Решение
Из файла получается $P=X/S$ сегментов, и столько же пакетов размера $80+S$. По формуле из задачи 1 для передачи всех пактов потребуется
$$
(N - 1 + P) \cdot \frac L  R = (2 + X / S) \cdot \frac {80 + S} R
$$ 
времени. Следовательно, нам надо, имея контроль над $S$, минимизировать величину
$$
(2 + X / S) \cdot (80 + S) \to \min \iff 160 + 80X/S + 2S + X \to\min\\
\iff 80X/S+2S \to \min \iff 40X/S + S\to\min.
$$
Продифференцирем по $S$:
$$
(40X / S + S)'_S = -40X/S^2 + 1 = 0 \iff S^2 = 40X \iff S = 2\sqrt{10X}.
$$
При таком $S$ достигается наименьшая задержка передачи.

### Задание 5 (2 балла)
Рассмотрим задержку ожидания в буфере маршрутизатора. Обозначим через $I$ интенсивность
трафика, то есть $I = \dfrac{L a}{R}$.
Предположим, что для $I < 1$ задержка ожидания вычисляется как $\dfrac{I \cdot L}{R (1 – I)}$. 
1. Напишите формулу для общей задержки, то есть суммы задержек ожидания и передачи.
2. Опишите зависимость величины общей задержки от значения $\dfrac{L}{R}$.

#### Решение
1.
$$
\frac{IL}{R(1-I)} + \frac L R = \frac L {R(1-I)}.
$$
2. Если $x=L/R$, то
$$
\frac L {R(1-I)} = \frac x {(1-ax)}.
$$
