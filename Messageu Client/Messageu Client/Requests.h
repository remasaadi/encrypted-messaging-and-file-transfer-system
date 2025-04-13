#pragma once

#include <vector>
#include <string>
#include "Communication.h"  // שימוש במחלקת תקשורת שעברה התאמה ל-Boost
#include "Client.h"
class Requests {
public:
    // קונסטרקטור שמקבל הפניה למחלקת התקשורת
    Requests(Communication& comm);

    // שליחת בקשה לקבלת רשימת הלקוחות מהשרת
    void requestClientsList();

private:
    Communication& comm;  // שמירת הפניה לאובייקט תקשורת קיים
};
