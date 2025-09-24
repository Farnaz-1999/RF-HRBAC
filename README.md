# FR_HRBAC
FR_HRBAC is an access control model for IoT-based systems, especially healthcare systems.

* Create Envirenment:
  >python3 -m venv FR_HRBAC


* Activate Enviernment:

  (in MacOS):  
    >source FR_HRBAC/bin/activate
  
  (in Windows):
    >.\FR_HRBAC\Scripts\bin\activate


* Install Requierments:
  >pip install -r requirements.txt


* Run Server:
  >cd server

  >python -m uvicorn main:app --reload

  
in tests directory test.py is available with a method that you can use to test the model.

