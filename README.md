# Лабораторная работа №1  
## Часть 1. Запуск программ  

### Отчет по лабораторной работе  
**Студент:** [Ватан Хатиб]  
**Группа:** [P3319]  
**Преподаватель:** [Осипов Святослав Владимирович]  
**Вариант:** Использование `vfork` для создания дочерних процессов  

---

### Текст задания  
1. Необходимо реализовать собственную оболочку командной строки - shell.  
2. Shell должен предоставлять возможность запускать программы с аргументами и выводить реальное время работы программы.  

---

### Описание программы  

Программа реализует оболочку командной строки, предоставляя следующие функциональные возможности:  
1. Ввод команд с аргументами.  
2. Использование встроенных команд `cd` и `exit`.  
3. Запуск внешних программ с использованием системных вызовов.  
4. Подсчет и вывод времени выполнения программы.  

**Основные аспекты реализации:**  
- Для ввода команд используется библиотека `readline`, которая обеспечивает удобство работы с историей команд.  
- Для создания новых процессов используется системный вызов `fork`.  
- Время выполнения программы измеряется с использованием функции `clock_gettime` с монотонными часами (`CLOCK_MONOTONIC`), что позволяет избежать влияния изменения системного времени.  

**Входные данные:**  
Команда и аргументы, введенные пользователем.  

**Выходные данные:**  
1. Результат выполнения команды (выводится дочерним процессом).  
2. Реальное время выполнения команды.  

---

### Структура программы  

Код программы размещен в файле `shell.c`.  

**Основные функции программы:**  
1. `parse_input` — разбирает введенную строку на команду и аргументы.  
2. `handle_special_commands` — обрабатывает встроенные команды `exit` и `cd`.  
3. Основной цикл обработки команд:  
    - Считывание команды с использованием `readline`.  
    - Разбор команды и аргументов.  
    - Запуск программы в дочернем процессе с использованием системного вызова `fork`.  
    - Подсчет времени выполнения программы.  

**Пример запуска оболочки:** 
```
shell> ls -la Execution time: 0.003 seconds
shell> cd /home shell> exit
```
### Вывод  

Программа успешно реализует функционал оболочки командной строки:  
1. Обеспечивает запуск программ с аргументами.  
2. Отображает время выполнения программ.  
3. Поддерживает встроенные команды `cd` и `exit`.  

Данная реализация соответствует требованиям первой части задания

