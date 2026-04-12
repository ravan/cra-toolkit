using JsonConvert = Newtonsoft.Json.JsonConvert;

namespace MyApp
{
    public class App
    {
        public static void Main(string[] args)
        {
            var result = JsonConvert.DeserializeObject<string>("{}");
        }
    }
}
