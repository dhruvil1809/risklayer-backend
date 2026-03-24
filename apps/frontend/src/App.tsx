import AppRoutes from "./routes/appRoutes";
import ScrollToTop from "./components/ScrollToTop";
import { Toaster } from "react-hot-toast";

function App() {

  return (
    <>
      <ScrollToTop />
      <Toaster position="top-center" />
      <AppRoutes />
    </>
  )
}

export default App
